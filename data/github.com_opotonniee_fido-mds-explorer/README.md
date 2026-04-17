# opotonniee — fido-mds-explorer

**Source:** https://github.com/opotonniee/fido-mds-explorer
**Maintained by:** [opotonniee](https://github.com/opotonniee) (community GitHub project)

## What this data is

The FIDO Alliance Metadata Service (MDS3) distributes a signed JWT blob containing metadata for
every FIDO-certified authenticator. Relying parties use it to look up security status, attestation
certificates, and policy requirements for authenticators they encounter during WebAuthn registration.

The `fido-mds-explorer` repository acts as an incidental historical archive of that blob: each
commit adds the current `mds.blob` from `mds3.fidoalliance.org`, creating a timestamped record of
every version of the MDS data since mid-2021.

## What the blob is

`mds.blob` is the raw JWT (JSON Web Signature) served by the FIDO Alliance MDS3 endpoint. It has
the standard three-part JWT structure (`header.payload.signature`), where:

- **Header** — contains the `x5c` certificate chain used to verify the signature, rooted at the
  GlobalSign R3 CA
- **Payload** — a JSON object with a `legalHeader`, a `no` (sequence number), a `nextUpdate` date,
  and an `entries` array of authenticator metadata records
- **Signature** — RS256 or ES256 signature over the header and payload, verifiable with the leaf
  certificate from the `x5c` chain

Each entry in `entries` covers one authenticator model and includes its AAGUID or attestation
certificate root, a human-readable description, status reports (certification level, effective date,
reason), and the `metadataStatement` with full technical detail.

## How it is built and maintained

The `fido-mds-explorer` project is a community tool for browsing and analysing MDS data. Its author
commits updated blob snapshots as the FIDO Alliance publishes them. Because the repository tracks
every change to `mds.blob`, its commit history is a useful longitudinal record of how MDS entries
have been added, updated, or revoked over time.

The FIDO Alliance updates the blob on an irregular schedule, typically multiple times per month. The
`nextUpdate` field in the payload indicates when a new blob is expected.

## Data collected here

Files are stored in the `journal/` subdirectory. A file is only written when its content differs
from the most recently saved file, so each file represents a distinct version of the blob.

**File naming:** `journal/YYYYMMDD_mds.blob`, where the date is the UTC commit date from GitHub.

The files are stored as raw JWT text — the full signed blob, not the decoded payload. To read the
payload, base64url-decode the middle section of the dot-separated token.

## Relationship to other MDS data

This directory stores the raw signed blobs as archived by the fido-mds-explorer project. A separate
script (`scripts/fetch-fido-mds.py`) fetches the current blob directly from the FIDO Alliance,
validates the certificate chain and signature, and saves the decoded JSON payload to
`data/fidoalliance.org_metadata_service/`.
