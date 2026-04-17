#!/usr/bin/env python3
"""Validate a FIDO Alliance Metadata Service (MDS3) JWT blob.

One of the following options is required:

  --current     Download the current MDS3 JWT blob from mds3.fidoalliance.org
                and validate it. Certificate expiry is checked.

  --file PATH   Validate a local MDS3 JWT blob file. Certificate expiry is not
                checked, allowing validation of historical blobs with expired certs.

Validation covers the full certificate chain (issuer/subject matching and
cryptographic signatures) rooted at the GlobalSign R3 CA, plus the JWT signature.
The decoded payload is not saved anywhere.
"""

import argparse
import asyncio
import base64
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiohttp
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

MDS3_URL = "https://mds3.fidoalliance.org/"
ROOT_CERT_URL = "https://valid.r3.roots.globalsign.com/"


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Parsed namespace with either ``fetch`` (bool) or ``file`` (Path) set.
    """
    parser = argparse.ArgumentParser(
        description="Validate a FIDO MDS3 JWT blob against the GlobalSign R3 root."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--current",
        action="store_true",
        help="Download the current MDS3 blob from mds3.fidoalliance.org and validate it.",
    )
    source.add_argument(
        "--file",
        metavar="PATH",
        type=Path,
        help="Validate a local MDS3 blob file.",
    )
    return parser.parse_args()


async def download_root_cert(session: aiohttp.ClientSession) -> x509.Certificate:
    """Download the GlobalSign R3 root certificate from its canonical URL.

    The certificate is embedded as PEM inside an HTML page.

    Args:
        session: Active aiohttp client session.

    Returns:
        Parsed X.509 root certificate.

    Raises:
        ValueError: If the PEM block cannot be found in the response.
    """
    async with session.get(ROOT_CERT_URL) as resp:
        resp.raise_for_status()
        html = await resp.text()

    match = re.search(
        r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
        html,
        re.DOTALL,
    )
    if not match:
        raise ValueError(f"PEM certificate block not found in response from {ROOT_CERT_URL}")

    return x509.load_pem_x509_certificate(match.group(1).encode())


async def download_mds3_blob(session: aiohttp.ClientSession) -> str:
    """Download the raw MDS3 JWT blob.

    Args:
        session: Active aiohttp client session.

    Returns:
        Raw JWT string (three base64url-encoded parts joined by '.').
    """
    async with session.get(MDS3_URL) as resp:
        resp.raise_for_status()
        return await resp.text()


def _base64url_decode(data: str) -> bytes:
    """Decode a base64url-encoded string, adding padding as needed."""
    remainder = len(data) % 4
    if remainder:
        data += "=" * (4 - remainder)
    return base64.urlsafe_b64decode(data)


def _verify_cert_signed_by(
    cert: x509.Certificate, issuer: x509.Certificate, check_expiry: bool = True
) -> None:
    """Verify that cert was issued and signed by issuer.

    Args:
        cert: The certificate to verify.
        issuer: The certificate that should have signed cert.
        check_expiry: If True, reject certificates whose validity period does not
            include the current time. Set to False when validating historical blobs
            whose embedded certificates have since expired.

    Raises:
        ValueError: If issuer name doesn't match or signature is invalid.
    """
    if cert.issuer != issuer.subject:
        raise ValueError(
            f"Issuer mismatch: cert.issuer={cert.issuer.rfc4514_string()!r} "
            f"!= issuer.subject={issuer.subject.rfc4514_string()!r}"
        )

    if check_expiry:
        now = datetime.now(timezone.utc)
        for c in (cert, issuer):
            if not (c.not_valid_before_utc <= now <= c.not_valid_after_utc):
                raise ValueError(
                    f"Certificate {c.subject.rfc4514_string()!r} is not valid at {now.isoformat()} "
                    f"(valid {c.not_valid_before_utc.isoformat()} – {c.not_valid_after_utc.isoformat()})"
                )

    pub_key = issuer.public_key()
    if isinstance(pub_key, rsa.RSAPublicKey):
        pub_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,  # type: ignore[arg-type]
        )
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        pub_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),  # type: ignore[arg-type]
        )
    else:
        raise ValueError(f"Unsupported public key type: {type(pub_key).__name__}")


def validate_mds3_jwt(
    jwt_token: str, root_cert: x509.Certificate, check_expiry: bool = True
) -> dict[str, Any]:
    """Validate the MDS3 JWT blob and return the decoded payload.

    Performs full certificate chain validation (issuer/subject matching,
    cryptographic signatures, and optionally validity dates) then verifies the JWT
    signature using the leaf certificate's public key.

    Args:
        jwt_token: Raw JWT string from mds3.fidoalliance.org.
        root_cert: Trusted GlobalSign R3 root certificate.
        check_expiry: If True (default), reject expired certificates. Set to False
            when validating historical blobs whose embedded certificates have expired.

    Returns:
        Decoded JSON payload as a dict.

    Raises:
        ValueError: If chain validation or JWT signature verification fails.
    """
    parts = jwt_token.strip().split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT: expected 3 dot-separated parts, got {len(parts)}")

    header_b64, payload_b64, sig_b64 = parts

    header = json.loads(_base64url_decode(header_b64))
    x5c: list[str] | None = header.get("x5c")
    if not x5c:
        raise ValueError("JWT header is missing the x5c certificate chain field")

    certs = [x509.load_der_x509_certificate(base64.b64decode(entry)) for entry in x5c]
    print(f"[INFO] Certificate chain length: {len(certs)}", file=sys.stderr)

    # Validate the chain: certs[0] (leaf) → ... → certs[-1] → root_cert
    chain = certs + [root_cert]
    for i in range(len(chain) - 1):
        print(
            f"[INFO] Verifying cert[{i}] ({chain[i].subject.rfc4514_string()!r}) "
            f"signed by cert[{i + 1}]",
            file=sys.stderr,
        )
        _verify_cert_signed_by(chain[i], chain[i + 1], check_expiry=check_expiry)

    # Verify the JWT signature using the leaf certificate's public key
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = _base64url_decode(sig_b64)
    leaf_pub = certs[0].public_key()

    alg = header.get("alg", "")
    if alg == "RS256" or isinstance(leaf_pub, rsa.RSAPublicKey):
        if not isinstance(leaf_pub, rsa.RSAPublicKey):
            raise ValueError(f"alg={alg!r} but leaf public key is {type(leaf_pub).__name__}")
        leaf_pub.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    elif alg == "ES256" or isinstance(leaf_pub, ec.EllipticCurvePublicKey):
        if not isinstance(leaf_pub, ec.EllipticCurvePublicKey):
            raise ValueError(f"alg={alg!r} but leaf public key is {type(leaf_pub).__name__}")
        leaf_pub.verify(signature, signing_input, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError(f"Unsupported JWT algorithm: {alg!r}")

    print("[INFO] JWT signature verified successfully", file=sys.stderr)
    return json.loads(_base64url_decode(payload_b64))


async def main() -> None:
    """Validate a FIDO MDS3 JWT blob."""
    args = parse_args()

    async with aiohttp.ClientSession() as session:
        # Root certificate (needed for validation in both modes)
        print(f"[INFO] Downloading root certificate from {ROOT_CERT_URL}", file=sys.stderr)
        try:
            root_cert = await download_root_cert(session)
        except Exception as exc:
            print(f"[ERROR] Failed to download root certificate: {exc}", file=sys.stderr)
            sys.exit(1)
        print(f"[INFO] Root cert: {root_cert.subject.rfc4514_string()!r}", file=sys.stderr)

        # MDS3 JWT blob — fetch from network or read from local file
        if args.current:
            print(f"[INFO] Downloading MDS3 JWT blob from {MDS3_URL}", file=sys.stderr)
            try:
                jwt_token = await download_mds3_blob(session)
            except Exception as exc:
                print(f"[ERROR] Failed to download MDS3 blob: {exc}", file=sys.stderr)
                sys.exit(1)
        else:
            print(f"[INFO] Reading MDS3 JWT blob from {args.file}", file=sys.stderr)
            try:
                jwt_token = args.file.read_text()
            except OSError as exc:
                print(f"[ERROR] Failed to read {args.file}: {exc}", file=sys.stderr)
                sys.exit(1)

        print("[INFO] Validating MDS3 JWT (certificate chain + signature)...", file=sys.stderr)
        try:
            payload = validate_mds3_jwt(jwt_token, root_cert, check_expiry=args.current)
        except Exception as exc:
            print(f"[ERROR] MDS3 JWT validation failed: {exc}", file=sys.stderr)
            sys.exit(1)

        entry_count = len(payload.get("entries", []))
        next_update = payload.get("nextUpdate", "unknown")
        print(
            f"[INFO] Valid — {entry_count} entries, nextUpdate: {next_update}",
            file=sys.stderr,
        )


if __name__ == "__main__":
    asyncio.run(main())
