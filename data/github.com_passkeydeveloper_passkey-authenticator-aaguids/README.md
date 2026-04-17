# passkeydeveloper — Passkey Authenticator AAGUIDs

**Source:** https://github.com/passkeydeveloper/passkey-authenticator-aaguids
**Maintained by:** [passkeydeveloper](https://github.com/passkeydeveloper) (community-maintained GitHub project)

## What this data is

An AAGUID (Authenticator Attestation GUID) is a UUID assigned to a specific authenticator model or
implementation. During WebAuthn registration, authenticators include their AAGUID in the attestation
data, allowing relying parties to identify which authenticator was used.

This repository maps AAGUIDs to human-readable metadata — display names and branding icons — for
passkey-capable authenticators. It covers both platform authenticators (e.g. Windows Hello, Chrome
on Mac, iCloud Keychain) and roaming software authenticators (e.g. password managers such as Google
Password Manager, Dashlane, 1Password).

The repository describes itself as:

> "A community sourced list of AAGUID values for passkey provider metadata."

## How it is built and maintained

The data is community-maintained via pull requests on GitHub. Authenticator vendors and developers
submit their AAGUID entries directly. The project has no formal affiliation with the FIDO Alliance
or any standards body — it is a grassroots reference used by relying parties to display recognisable
authenticator names and logos in their UIs.

The repository contains two files at its root:

- `aaguid.json` — the AAGUID-to-metadata map
- `aaguid.json.schema` — JSON Schema for the above

Contributions can be submitted by opening a pull request against the GitHub repository.

## Data collected here

This directory stores dated snapshots of `aaguid.json` and `aaguid.json.schema`, downloaded at each
commit that changed them. Files are only written when the content differs from the most recently
saved file, so each file represents a distinct version of the upstream data.

**File naming:** `YYYYMMDD_aaguid.json` and `YYYYMMDD_aaguid.json.schema`, where the date is the
UTC commit date from GitHub.

### aaguid.json schema

The top-level object is a map from AAGUID string (UUID format) to an authenticator entry:

| Field | Required | Description |
|---|---|---|
| `name` | Yes | Display name of the authenticator or passkey provider |
| `icon_dark` | No | SVG icon encoded as a base64 data URI, intended for dark backgrounds |
| `icon_light` | No | SVG icon encoded as a base64 data URI, intended for light backgrounds |

The `icon_dark` and `icon_light` fields were added in August 2023; earlier snapshots contain only
`name`.

## About the passkeydeveloper project

passkeydeveloper is a GitHub organisation that publishes community tools and reference data for
passkey implementers. The AAGUID list is its primary artifact and is widely referenced by WebAuthn
libraries and relying party implementations that want to display authenticator branding.
