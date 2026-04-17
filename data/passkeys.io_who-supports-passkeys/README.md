# passkeys.io — Who Supports Passkeys

**Source:** https://www.passkeys.io/who-supports-passkeys
**Maintained by:** [Hanko.io](https://www.hanko.io) (Hanko GmbH, Kiel, Germany)

## What this list is

This is a curated directory of websites and apps that have deployed passkeys as
a full password alternative. It is published and maintained by Hanko GmbH, the
company behind the open source authentication platform [Hanko](https://www.hanko.io)
and the passkey demo site [passkeys.io](https://www.passkeys.io).

The list is intentionally narrow in scope. The site states:

> "This list only shows websites and apps that have implemented passkeys as a
> full password alternative. That means that the passkey option has to be
> visible on the main login screen."

## What is and is not included

**Included:** Services where a passkey prompt appears on the main login screen
without requiring prior username entry, and where passkeys function as the
primary authentication method (not just as a second factor).

**Not included:**
- Services that require a username to be entered before the passkey option is
  presented
- Services that use WebAuthn/passkeys only as a 2FA method (i.e. on top of a
  password)

This makes the list shorter but more meaningful than broader passkey
compatibility lists — it specifically tracks consumer-facing deployments where
passkeys replace passwords end-to-end.

## How it is built and maintained

The list is manually curated by the Hanko team. The website includes a public
submission form where anyone can suggest a missing website or app. Submissions
ask for the website name, URL, and an optional message.

The page is built with Webflow and does not expose an API or structured data
feed. Entries are embedded directly in the page HTML.

## Data collected here

The `inventory.json` file in this directory is scraped from the page HTML and
contains one entry per listed company:

| Field | Description |
|---|---|
| `company` | Display name of the company or service |
| `frontpage_url` | URL linked from the directory entry (`null` if not provided). Sourced directly from the site and not independently validated. |

No images or additional metadata are present on the page. Entries are sorted
alphabetically by company name.

## About Hanko

Hanko GmbH is a Germany-based software company specializing in open source
authentication and user management. Their core product, Hanko, is an
AGPLv3-licensed authentication server supporting passkeys, passwords, 2FA, and
SSO. They also offer a standalone FIDO2-certified Passkey API and a set of
framework-agnostic web components called Hanko Elements.

passkeys.io is run by Hanko as a public passkey demo and information resource.
It includes a live passkey login demo, device compatibility tables, and the
"who supports passkeys" directory documented here.
