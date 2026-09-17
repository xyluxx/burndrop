"""JSON string encoding that is byte-identical to Go's encoding/json.

The Go reference encodes envelopes with ``json.Encoder`` and
``SetEscapeHTML(false)``. Python's ``json`` module differs in two places:
it never escapes U+2028 and U+2029, and it cannot represent invalid UTF-8
the way Go does. This module reproduces Go's rules exactly so that an
envelope encoded here matches the shared test vectors byte for byte.

Escape sequences are assembled from ``chr(92)`` so that no tool that
rewrites backslash escapes in source files can change them.
"""

from __future__ import annotations

__all__ = ["json_string"]

_BS = chr(92)
_HEX = "0123456789abcdef"
_SHORT = {
    '"': _BS + '"',
    _BS: _BS + _BS,
    chr(10): _BS + "n",
    chr(13): _BS + "r",
    chr(9): _BS + "t",
    chr(8): _BS + "b",
    chr(12): _BS + "f",
}
_HTML = {"<", ">", "&"}
# Go always escapes the line separators, and writes the six character
# escape for every byte that is not valid UTF-8 (a lone surrogate here).
_LINE_SEPARATORS = {chr(0x2028), chr(0x2029)}
_BACKSLASH_U = _BS + "u"
_REPLACEMENT = _BACKSLASH_U + "fffd"


def json_string(text: str, escape_html: bool = False) -> str:
    """Return the JSON string literal for text, quotes included."""
    out = ['"']
    for ch in text:
        code = ord(ch)
        short = _SHORT.get(ch)
        if short is not None:
            out.append(short)
        elif code < 0x20 or (escape_html and ch in _HTML):
            out.append(_BACKSLASH_U + "00" + _HEX[code >> 4] + _HEX[code & 0xF])
        elif ch in _LINE_SEPARATORS:
            out.append(_BACKSLASH_U + format(code, "04x"))
        elif 0xD800 <= code <= 0xDFFF:
            out.append(_REPLACEMENT)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)
