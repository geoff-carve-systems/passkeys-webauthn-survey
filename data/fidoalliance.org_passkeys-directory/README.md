# FIDO Alliance — Passkey Directory

**Source:** https://fidoalliance.org/passkeys-directory/
**Maintained by:** [FIDO Alliance](https://fidoalliance.org)

## What this list is

This is a curated directory of active passkey deployment examples, published
by the FIDO Alliance. The page describes it as:

> "An interactive resource that lists active FIDO passkey implementation
> examples, both for consumers and in the workforce. It also indicates what
> the user experience is — whether the passkey is synced and available across
> devices, or the passkey is bound and available on a single device such as a
> FIDO security key or within a mobile app."

The Alliance notes that this is not an exhaustive list of deployments and is
updated regularly.

## Implementation types

The directory separates entries into two tracks:

- **Consumer** — passkey implementations aimed at end users (the large
  majority of entries)
- **Workforce** — passkey implementations in enterprise or employee-facing
  contexts

The scraper must be run once per type; both are stored together in
`inventory.json` distinguished by the `implementation_type` field.

## How it is built and maintained

The directory is manually curated by the FIDO Alliance. Contributions can be
submitted by emailing marketing@fidoalliance.org.

The page is a JavaScript-rendered WordPress site. Entries are loaded
dynamically and gated behind consumer/workforce filter checkboxes and a
"load all" button, requiring a headless browser (Playwright) to scrape.
Each entry links to a "learn more" page with additional detail about the
specific deployment.

## Data collected here

The `inventory.json` file contains one entry per logo image filename.

| Field | Description |
|---|---|
| `image` | Logo image filename (file lives in the `images/` subdirectory) |
| `learn_more_url` | URL to the FIDO Alliance detail page for this deployment, or `null` |
| `implementation_type` | `"consumer"` or `"workforce"` |
| `company` | Display name of the company or service. Populated manually after entry is created. |
| `frontpage_url` | URL of the company's website. Populated and validated manually. |

Entries are sorted alphabetically by image filename.

## About the FIDO Alliance

The FIDO Alliance is an open industry association headquartered in Beaverton,
Oregon, with a mission to reduce the world's reliance on passwords. It
develops the open authentication standards underpinning passkeys: FIDO2, the
W3C Web Authentication (WebAuthn) specification, and the Client to
Authenticator Protocol (CTAP). Members include hundreds of global technology
companies across enterprise, payments, telecom, government, and healthcare.

The Alliance also operates certification programs for authenticators and
servers, and runs the FIDO Metadata Service (MDS), which provides
cryptographic metadata about certified authenticators.
