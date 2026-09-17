"""Verify every spec/interop/*.json with the Python SDK.

Run from sdk/python so the package is importable:

    uv run python ../../spec/interop/python_check.py [file ...]

Without arguments every *.json next to this script is checked, including
python.json (a self check). The exit status is 1 when any case fails. The
checks are listed in README.md next to this file. The single-case layout
written by the TypeScript scripts (``sealed`` and ``aead`` objects) is
accepted as well and mapped onto the same checks.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from burndrop import crypto, password
from burndrop.encoding import EncodingError, b64decode, b64encode

HERE = Path(__file__).resolve().parent
AAD_PREFIX = "burndrop/reveal/v1"


class Failure(Exception):
    """One check did not hold."""


def _bytes(case: dict[str, Any], field: str, length: int | None = None) -> bytes:
    value = case.get(field)
    if not isinstance(value, str):
        raise Failure(f"{field} is missing or not a string")
    try:
        data = b64decode(value)
    except EncodingError as err:
        raise Failure(f"{field} is not canonical base64url") from err
    if length is not None and len(data) != length:
        raise Failure(f"{field} must be {length} bytes, got {len(data)}")
    return data


def _expected_envelope(case: dict[str, Any]) -> crypto.Envelope:
    obj = case.get("envelope")
    if not isinstance(obj, dict):
        raise Failure("envelope is missing or not an object")
    try:
        return crypto.Envelope(**obj)
    except TypeError as err:
        raise Failure(f"envelope has unexpected fields: {err}") from err


def _check_plaintext(
    padded: bytes, case: dict[str, Any], expected_type: str
) -> tuple[crypto.Envelope, list[str]]:
    notes: list[str] = []
    try:
        plaintext = crypto.unpad(padded, crypto.PAD_BLOCK)
    except crypto.PaddingError as err:
        raise Failure("padding is malformed") from err
    if "plaintext" in case and plaintext != _bytes(case, "plaintext"):
        raise Failure("unpadded plaintext differs from the plaintext field")
    try:
        decoded = crypto.Envelope.decode(plaintext)
    except crypto.EnvelopeError as err:
        raise Failure(f"envelope does not decode: {err}") from err
    expected = _expected_envelope(case)
    if decoded != expected:
        raise Failure(f"decoded envelope differs: {decoded!r} != {expected!r}")
    if decoded.type != expected_type:
        raise Failure(f"envelope type is {decoded.type!r}, want {expected_type!r}")
    if "secret" in case and decoded.secret_bytes() != _bytes(case, "secret"):
        raise Failure("secret bytes differ from the secret field")
    if decoded.encode() != plaintext:
        notes.append("re-encoding differs from the producer's bytes (informational)")
    return decoded, notes


def check_drop(case: dict[str, Any]) -> list[str]:
    public_key = _bytes(case, "recipient_public_key", crypto.KEY_SIZE)
    private_key = _bytes(case, "recipient_secret_key", crypto.KEY_SIZE)
    if crypto.public_key_from_private(private_key) != public_key:
        raise Failure("public key is not derived from the secret key")
    fingerprint = crypto.fingerprint(public_key)
    if "fingerprint" in case and case["fingerprint"] != fingerprint:
        raise Failure("fingerprint differs")
    if "commitment" in case and case["commitment"] != crypto.commitment(public_key):
        raise Failure("commitment differs")
    try:
        padded = crypto.open_sealed(public_key, private_key, _bytes(case, "sealed"))
    except crypto.DecryptError as err:
        raise Failure("sealed box does not open") from err
    decoded, notes = _check_plaintext(padded, case, crypto.TYPE_DROP)
    if decoded.fingerprint != fingerprint:
        raise Failure("envelope fingerprint differs from the key fingerprint")
    return notes


def check_reveal(case: dict[str, Any]) -> list[str]:
    key = _bytes(case, "key", crypto.KEY_SIZE)
    link_key = key
    if "salt" in case:
        salt = _bytes(case, "salt", password.SALT_SIZE)
        reveal_password = case.get("password")
        if not isinstance(reveal_password, str):
            raise Failure("password must be a string when salt is present")
        key = password.reveal_key_with_password(link_key, reveal_password, salt)
    display_name = case.get("display_name")
    keeps_copy = case.get("keeps_copy")
    if not isinstance(display_name, str) or not isinstance(keeps_copy, bool):
        raise Failure("display_name must be a string and keeps_copy a boolean")
    aad = _bytes(case, "aad")
    if aad != crypto.reveal_aad(display_name, keeps_copy):
        raise Failure("aad differs from reveal_aad(display_name, keeps_copy)")
    blob = _bytes(case, "blob")
    if "nonce" in case and blob[: crypto.NONCE_SIZE] != _bytes(case, "nonce", crypto.NONCE_SIZE):
        raise Failure("blob does not start with the nonce")
    try:
        padded = crypto.decrypt_aead(key, blob, aad)
    except crypto.DecryptError as err:
        raise Failure("blob does not decrypt") from err
    _decoded, notes = _check_plaintext(padded, case, crypto.TYPE_REVEAL)
    try:
        crypto.decrypt_aead(key, blob, crypto.reveal_aad(display_name, not keeps_copy))
    except crypto.DecryptError:
        pass
    else:
        raise Failure("blob decrypts with keeps_copy flipped; the display fields are not bound")
    if key != link_key:
        try:
            crypto.decrypt_aead(link_key, blob, aad)
        except crypto.DecryptError:
            pass
        else:
            raise Failure("blob decrypts with the link key alone; the password is not mixed in")
    return notes


def _from_single_case_layout(document: dict[str, Any]) -> dict[str, Any] | None:
    """Map the TypeScript layout (one ``sealed`` and one ``aead`` object) onto the schema.

    Returns None when the document does not use that layout.
    """
    if "drops" in document or "reveals" in document:
        return None
    sealed = document.get("sealed")
    aead = document.get("aead")
    if not isinstance(sealed, dict) and not isinstance(aead, dict):
        return None
    out: dict[str, Any] = {
        "version": 1,
        "producer": document.get("producer", "?"),
        "drops": [],
        "reveals": [],
    }
    if isinstance(sealed, dict):
        out["drops"].append(
            {
                "name": "sealed",
                "recipient_public_key": sealed.get("public_key"),
                "recipient_secret_key": sealed.get("private_key"),
                "sealed": sealed.get("ciphertext"),
                "envelope": sealed.get("plaintext_envelope"),
            }
        )
    if isinstance(aead, dict):
        case: dict[str, Any] = {
            "name": "aead",
            "key": aead.get("key"),
            "blob": aead.get("ciphertext"),
            "envelope": aead.get("plaintext_envelope"),
        }
        aad = aead.get("aad")
        if isinstance(aad, str):
            # The aad is given as text in this layout, not base64url.
            parts = aad.split("\n")
            if len(parts) == 3 and parts[0] == AAD_PREFIX and parts[2] in ("0", "1"):
                case["display_name"] = parts[1]
                case["keeps_copy"] = parts[2] == "1"
            case["aad"] = b64encode(aad.encode("utf-8"))
        out["reveals"].append(case)
    return out


def check_file(path: Path) -> tuple[int, int]:
    """Return (passed, failed) counts for one file."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as err:
        print(f"FAIL {path.name}: not JSON: {err}")
        return 0, 1
    if not isinstance(document, dict):
        print(f"FAIL {path.name}: not a JSON object")
        return 0, 1
    mapped = _from_single_case_layout(document)
    if mapped is not None:
        document = mapped
    elif document.get("version") != 1:
        print(f"FAIL {path.name}: version must be 1")
        return 0, 1
    producer = document.get("producer", "?")
    passed = failed = 0
    for kind, check in (("drops", check_drop), ("reveals", check_reveal)):
        cases = document.get(kind, [])
        if not isinstance(cases, list):
            print(f"FAIL {path.name}: {kind} must be a list")
            failed += 1
            continue
        for index, case in enumerate(cases):
            label = case.get("name", str(index)) if isinstance(case, dict) else str(index)
            try:
                if not isinstance(case, dict):
                    raise Failure("case is not an object")
                notes = check(case)
            except Failure as err:
                print(f"FAIL {path.name} [{producer}] {kind[:-1]} {label!r}: {err}")
                failed += 1
                continue
            suffix = "; ".join(notes)
            print(
                f"ok   {path.name} [{producer}] {kind[:-1]} {label!r}"
                + (f" ({suffix})" if suffix else "")
            )
            passed += 1
    if passed + failed == 0:
        print(f"FAIL {path.name}: no cases")
        failed += 1
    return passed, failed


def main(argv: list[str]) -> int:
    paths = [Path(arg) for arg in argv] or sorted(HERE.glob("*.json"))
    if not paths:
        print("no interop files found")
        return 1
    total_passed = total_failed = 0
    for path in paths:
        passed, failed = check_file(path)
        total_passed += passed
        total_failed += failed
    print(f"{total_passed} passed, {total_failed} failed, {len(paths)} file(s)")
    return 1 if total_failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
