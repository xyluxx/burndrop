"""RFC 3339 timestamps, parsed as strictly as Go's ``time.Parse``.

Go's ``time.RFC3339`` layout requires a four digit year, an uppercase ``T``
separator, an uppercase ``Z`` or a numeric ``+hh:mm`` offset, and every
field within range (including the day of month for the given month). A
fractional second is optional. Python's ``datetime.fromisoformat`` accepts
far more shapes, so a dedicated parser is used instead.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

__all__ = ["format_rfc3339", "parse_rfc3339"]

_RFC3339 = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:[.,](\d+))?(Z|[+-]\d{2}:\d{2})"
)


def _is_leap(year: int) -> bool:
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def _days_in_month(month: int, year: int) -> int:
    if month == 2:
        return 29 if _is_leap(year) else 28
    if month in (4, 6, 9, 11):
        return 30
    return 31


def parse_rfc3339(text: str) -> datetime:
    """Parse an RFC 3339 timestamp into an aware datetime.

    Raises ValueError for anything Go's ``time.Parse(time.RFC3339, s)``
    would reject. Fractional seconds beyond microseconds are truncated.
    """
    match = _RFC3339.fullmatch(text)
    if match is None:
        raise ValueError("not an RFC 3339 timestamp")
    year, month, day, hour, minute, second = (int(match.group(i)) for i in range(1, 7))
    if not 1 <= month <= 12:
        raise ValueError("month out of range")
    if not 1 <= day <= _days_in_month(month, year):
        raise ValueError("day out of range")
    if hour > 23 or minute > 59 or second > 59:
        raise ValueError("time out of range")
    if year == 0:
        # Go accepts year 0000; datetime cannot represent it.
        raise ValueError("year out of range")
    fraction = match.group(7) or ""
    microsecond = int((fraction + "000000")[:6]) if fraction else 0
    zone = match.group(8)
    if zone == "Z":
        tzinfo = timezone.utc
    else:
        offset_hours = int(zone[1:3])
        offset_minutes = int(zone[4:6])
        if offset_hours > 23 or offset_minutes > 59:
            raise ValueError("time zone offset out of range")
        delta = timedelta(hours=offset_hours, minutes=offset_minutes)
        tzinfo = timezone(-delta if zone[0] == "-" else delta)
    return datetime(year, month, day, hour, minute, second, microsecond, tzinfo=tzinfo)


def format_rfc3339(value: datetime) -> str:
    """Format a datetime the way the relay does: UTC, whole seconds, ``Z``."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
