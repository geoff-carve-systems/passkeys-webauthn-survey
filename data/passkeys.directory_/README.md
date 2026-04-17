# passkeys.directory

**Source:** https://passkeys.directory/
**Maintained by:** [1Password](https://1password.com)

## What this list is

passkeys.directory is a community-driven index of websites, apps, and services
that support signing in with passkeys. It is built and maintained by 1Password.

The directory covers only services with active passkey support — a separate
"vote for passkeys" wishlist of 4,000+ requested sites lives in the same
database but is excluded from this data.

## How it is built and maintained

Entries are submitted by the community and curated by 1Password. The site is
built with Gatsby and backed by a Supabase database. All data — including
notes, setup links, and dates — is stored in a single `sites` table and served
via the Supabase public REST API, which the scraper queries directly.

New entries can be suggested at https://passkeys.directory/request.

## Data collected here

The `inventory.json` file contains one entry per supported site, sorted
alphabetically by company name.

| Field | Description |
|---|---|
| `company` | Display name of the company or service |
| `domain` | Primary domain (used as the unique key) |
| `image` | Logo image filename in the `images/` subdirectory, or `null` if no image is available from the 1Password icon CDN |
| `frontpage_url` | URL of the company's website, or `null`. Sourced directly from the site and not independently validated. Not overwritten on re-scrapes once set. |
| `supported` | List of one or both of `"Sign In"` and `"MFA"` |
| `category` | Industry category as assigned in the directory |
| `date_added` | ISO date (YYYY-MM-DD) the entry was added to the directory |
| `setup_url` | Direct URL to the passkey setup page for this service |
| `additional_info_url` | URL to documentation or a help article, or `null` |
| `notes` | Free-text setup instructions or caveats, or `null`. May contain Markdown. |

## Notes on the data

**Categories** are freeform strings entered by submitters and are not
normalised — similar categories appear under different names (e.g. `eCommerce`
and `E-Commerce`, `Social Media`, `Social`, and `Social Networking`).

**`supported`** reflects the `passkey_signin` and `passkey_mfa` boolean flags
in the database:
- `Sign In` — passkeys can replace the password at sign-in
- `MFA` — passkeys are supported as a second factor on top of a password

**`notes`** is present for roughly half of entries and often contains
step-by-step setup instructions. The content is stored as Markdown in the
database and rendered as HTML on the detail page.

**Images** are downloaded from the 1Password icon CDN at
`cache.agilebits.com/richicons/images/login/120/{domain}.png`. About 35
entries have no image available from the CDN; their `image` field is `null`.

## About 1Password

1Password is a password manager and identity security platform. They publish
passkeys.directory as a public resource alongside their passkey products,
including Passage by 1Password (a passkey authentication SDK for developers)
and native passkey support within the 1Password manager itself.
