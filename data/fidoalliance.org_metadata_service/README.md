# FIDO Alliance — Metadata Service

**Source:** https://mds3.fidoalliance.org/ (MDS3) and https://c-mds.fidoalliance.org/ (c-MDS)
**Maintained by:** [FIDO Alliance](https://fidoalliance.org)

## What this data is

The FIDO Alliance Metadata Service (MDS) publishes cryptographic and display metadata
about certified FIDO authenticators. This directory captures two endpoints:

- **MDS3** — the authoritative FIDO Metadata Service 3 feed, published as a signed JWT
  blob. The payload contains metadata statements for each certified authenticator,
  including public key material, certification status, attestation root certificates, and
  detailed capability flags.
- **c-MDS** (Metadata Convenience Service) — a lightweight JSON feed keyed by AAGUID
  containing only display metadata: friendly names and icons. Intended for relying parties
  that need to render an authenticator's name and logo without parsing the full MDS3 JWT.

## How it is built and maintained

The FIDO Alliance updates the MDS3 feed on a rolling basis as authenticators gain, renew,
or lose certification. The c-MDS feed reflects the same corpus.

Files are downloaded by `scripts/fetch-fido-mds.py`. Each run writes a new
`YYYYMMDD_`-prefixed file to `journal/` only when the content has changed since the
previous download. Unchanged content is silently skipped, so the journal records only
meaningful updates.

## Data collected here

Files are stored in `journal/` with `YYYYMMDD_` prefixes.

### `YYYYMMDD_mds3.blob`

The raw MDS3 JWT as returned by `https://mds3.fidoalliance.org/`. A standard three-part
base64url-encoded JWT. The payload (middle part) contains a `entries` array; each entry
is a metadata statement for one authenticator identified by its AAGUID (for FIDO2/U2F
roaming authenticators) or AAID (for UAF authenticators).

### `YYYYMMDD_cmds.json`

A JSON object with one key per AAGUID (lowercase UUID format). Each value contains:

| Field | Description |
|---|---|
| `friendlyNames` | Object mapping BCP 47 language tags to display names (e.g. `"en-US"`) |
| `icon` | Data URI (`data:image/png;base64,...`) of the authenticator's logo, or absent |
| `iconDark` | Dark-mode variant of the logo, or absent |
| `providerLogoLight` | Light-mode provider/vendor logo, or absent |
| `providerLogoDark` | Dark-mode provider/vendor logo, or absent |

As of April 2026 the feed contains 327 entries, all with `en-US` friendly names.

## About the FIDO Alliance

The FIDO Alliance is an open industry association headquartered in Beaverton, Oregon,
with a mission to reduce the world's reliance on passwords. It develops the open
authentication standards underpinning passkeys: FIDO2, the W3C Web Authentication
(WebAuthn) specification, and the Client to Authenticator Protocol (CTAP). Members
include hundreds of global technology companies across enterprise, payments, telecom,
government, and healthcare.

The Alliance operates certification programs for authenticators and servers. The MDS is
the canonical registry of certified authenticator metadata and is widely used by WebAuthn
relying parties to verify attestation statements and display authenticator information to
users.
