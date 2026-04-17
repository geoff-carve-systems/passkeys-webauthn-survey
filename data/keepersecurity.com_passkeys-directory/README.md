# Keeper Security — Passkeys Directory

**Source:** https://www.keepersecurity.com/passkeys-directory/
**Maintained by:** [Keeper Security, Inc.](https://www.keepersecurity.com)

## What this list is

This is a curated directory of websites and apps that support passkey login,
published by Keeper Security as a free public resource. The page states:

> "We've compiled a complete list of websites that support logging in with
> passkeys. We'll be continuously adding to this directory, so be sure to
> check back often."

This directory distinguishes between two modes of passkey support per entry:

- **Sign-In Method** — the service supports passkeys as a primary
  authentication method
- **MFA** — the service supports passkeys as a multi-factor authentication
  step (i.e. on top of a password or other credential)

Entries can carry one or both labels.

## Categories

Entries are tagged with one of the following categories:

Authentication Provider, Automotive, E-Commerce, Education, Finance,
Government, Health & Wellness, Information Technology, Other, Productivity,
Real Estate, Social Media, Travel & Leisure

## How it is built and maintained

The directory is manually curated by the Keeper Security team. The page
includes a public Google Form submission link where anyone can request a new
entry. Submissions ask for the website name and URL.

The directory can be sorted by name or category, and filtered by support
type (Sign-In Method, MFA, or all). The page is rendered as static HTML with
all entry data embedded directly as `data-*` attributes, with no external API.

## Data collected here

The `inventory.json` file in this directory is scraped from the page HTML and
contains one entry per unique logo image filename. Where multiple entries share
the same image file, only the first occurrence is recorded.

| Field | Description |
|---|---|
| `image` | Logo image filename (file lives in the `images/` subdirectory) |
| `company` | Display name of the company or service |
| `category` | Industry category assigned by Keeper |
| `supported` | List of one or both of `"Sign-In Method"` and `"MFA"` |
| `frontpage_url` | URL of the company's website, or `null`. Populated and validated manually — not sourced from the Keeper page itself. |

Entries are sorted alphabetically by image filename.

## About Keeper Security

Keeper Security, Inc. is a Chicago-based cybersecurity company offering
password management and privileged access management (PAM) products for
consumers, businesses, and government. Their product line includes an
enterprise password manager, KeeperPAM for privileged access, a Secrets
Manager, and a Connection Manager. The passkeys directory is listed alongside
other free tools on their site (dark web scanners, password generators, etc.)
and ties into their passkey support within the Keeper Vault product. A user
guide for using passkeys with Keeper is available at
https://docs.keeper.io/user-guides/passkeys.
