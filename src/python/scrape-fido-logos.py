#!/usr/bin/env python3
"""
FIDO Alliance Passkeys Directory Logo Scraper

Downloads logo images from the FIDO Alliance passkeys directory and generates
an inventory JSON file with metadata for each logo.
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Dict, List

import aiohttp
from playwright.async_api import async_playwright, Page

# Configuration
OUTPUT_DIR = Path('./data/fidoalliance.org_passkeys-directory')
IMAGES_DIR = OUTPUT_DIR / 'images'
TARGET_URL = 'https://fidoalliance.org/passkeys-directory/'
INVENTORY_FILE = 'inventory.json'

# Files to exclude (navigation and language selection images)
EXCLUDE_FILES = {
    'close.svg',
    'cn.svg',
    'en-233cdf23.svg',
    'en.svg',
    'gb.svg',
    'ja-ac49466d.svg',
    'ja.svg',
    'jp.svg',
    'ko-0b1aedad.svg',
    'ko.svg',
    'kr.svg',
    'revisit.svg',
    'zh-hans-45cc20fd.svg',
    'zh-hans.svg',
    'fido-logo-v2.svg',
    'fido-logo-v2-1.svg',
    'fido-logo-v2-23c8f87b.svg',
    'poweredbtcky.svg',
    'enterprise.jpg'
}


def get_filename_from_url(url: str) -> str:
    """Extract filename from URL."""
    return Path(url).name.split('?')[0]


async def download_image(session: aiohttp.ClientSession, url: str, output_path: Path) -> None:
    """Download an image from URL to output path."""
    async with session.get(url) as response:
        response.raise_for_status()
        content = await response.read()
        output_path.write_bytes(content)


async def validate_page_structure(page: Page) -> Dict:
    """Validate that the page has the expected structure."""
    results = {
        'hasConsumerCheckbox': False,
        'hasWorkforceCheckbox': False,
        'hasLoadButton': False,
        'hasExpectedTitle': False,
        'errors': []
    }

    # Check for checkboxes
    checkboxes = await page.query_selector_all('input[type="checkbox"]')
    for checkbox in checkboxes:
        value = await checkbox.get_attribute('value') or ''
        checkbox_id = await checkbox.get_attribute('id') or ''

        # Get label text (label might wrap the checkbox or be a sibling)
        label_text = await checkbox.evaluate('el => el.closest("label")?.textContent || ""')
        sibling_text = await checkbox.evaluate('el => el.nextElementSibling?.textContent || ""')

        combined_text = f"{value} {checkbox_id} {label_text} {sibling_text}".lower()

        if 'consumer' in combined_text:
            results['hasConsumerCheckbox'] = True
        if 'workforce' in combined_text:
            results['hasWorkforceCheckbox'] = True

    # Check for load button
    buttons = await page.query_selector_all('button, input[type="button"], input[type="submit"]')
    for btn in buttons:
        text = (await btn.text_content() or '') + (await btn.get_attribute('value') or '')
        if 'load all' in text.lower() or 'load more' in text.lower():
            results['hasLoadButton'] = True
            break

    # Check page title/heading
    title = await page.title()
    h1_element = await page.query_selector('h1')
    h1_text = await h1_element.text_content() if h1_element else ''

    combined = f"{title} {h1_text}".lower()
    results['hasExpectedTitle'] = any(keyword in combined for keyword in ['passkey', 'fido', 'directory'])

    # Validate results
    if not results['hasConsumerCheckbox']:
        results['errors'].append('Consumer checkbox not found')
    if not results['hasWorkforceCheckbox']:
        results['errors'].append('Workforce checkbox not found')
    if not results['hasLoadButton']:
        results['errors'].append('Load all button not found')
    if not results['hasExpectedTitle']:
        results['errors'].append('Page title does not contain expected keywords (passkey/fido/directory)')

    return results


async def click_implementation_checkbox(page: Page, impl_type: str) -> None:
    """Click the checkbox for the specified implementation type."""
    print(f'Clicking {impl_type} checkbox...')

    checkboxes = await page.query_selector_all('input[type="checkbox"]')
    checkbox_found = False

    for checkbox in checkboxes:
        value = await checkbox.get_attribute('value') or ''
        checkbox_id = await checkbox.get_attribute('id') or ''

        if value == impl_type or checkbox_id == impl_type:
            await checkbox.click()
            checkbox_found = True
            break

        # Check label and sibling text
        label_text = (await checkbox.evaluate('el => el.closest("label")?.textContent || ""')).lower()
        sibling_text = (await checkbox.evaluate('el => el.nextElementSibling?.textContent || ""')).lower()

        if impl_type in label_text or impl_type in sibling_text:
            await checkbox.click()
            checkbox_found = True
            break

    if not checkbox_found:
        # Collect available checkboxes for error message
        available = []
        for checkbox in checkboxes:
            checkbox_id = await checkbox.get_attribute('id') or ''
            name = await checkbox.get_attribute('name') or ''
            value = await checkbox.get_attribute('value') or ''

            label_text = await checkbox.evaluate('el => el.closest("label")?.textContent || ""')
            sibling_text = await checkbox.evaluate('el => el.nextElementSibling?.textContent || ""')

            available.append({
                'id': checkbox_id,
                'name': name,
                'value': value,
                'label': f"{label_text} {sibling_text}".strip()
            })

        print(f'Could not find {impl_type} checkbox. Available checkboxes:', file=sys.stderr)
        print(available, file=sys.stderr)
        raise RuntimeError(f'{impl_type} checkbox not found')


async def click_load_all(page: Page) -> None:
    """Click the 'load all' button repeatedly until disabled."""
    print('Clicking "load all" button until disabled...')
    click_count = 0

    while True:
        # Find load all button
        buttons = await page.query_selector_all('button, input[type="button"], input[type="submit"]')
        load_button = None

        for btn in buttons:
            text = (await btn.text_content() or '') + (await btn.get_attribute('value') or '')
            if 'load all' in text.lower() or 'load more' in text.lower():
                load_button = btn
                break

        if not load_button:
            print('Load all button not found, assuming all content is loaded')
            break

        # Check if button is disabled
        is_disabled = await load_button.is_disabled()
        has_disabled_attr = await load_button.get_attribute('disabled') is not None
        has_disabled_class = 'disabled' in (await load_button.get_attribute('class') or '')

        if is_disabled or has_disabled_attr or has_disabled_class:
            print('Load all button is disabled, all content loaded')
            break

        # Click the button
        await load_button.click()
        click_count += 1
        print(f'  Clicked load all button ({click_count} times)')
        await asyncio.sleep(1.5)


async def extract_logo_data(page: Page) -> List[Dict]:
    """Extract logo information (image URL and learn more link)."""
    logo_data = []
    images = await page.query_selector_all('img')

    for img in images:
        src = await img.get_attribute('src')

        if not src or not src.startswith('http'):
            continue
        if 'FIDO_Passkey_mark' in src:
            continue

        filename = src.split('/')[-1].split('?')[0]
        if not filename:
            continue

        # Find learn more link in the same container
        learn_more_url = None

        # Find the closest container div/article/section/li
        # This small JS expression is simpler than XPath
        container_exists = await img.evaluate('el => !!el.closest("div, article, section, li")')

        if container_exists:
            # Get all links within the same container
            container_links = await img.evaluate('''el => {
                const container = el.closest("div, article, section, li");
                return Array.from(container.querySelectorAll("a"))
                    .filter(a => a.textContent.toLowerCase().includes("learn more"))
                    .map(a => a.href);
            }''')

            if container_links:
                learn_more_url = container_links[0]

        logo_data.append({
            'imageUrl': src,
            'learnMoreUrl': learn_more_url
        })

    return logo_data


def filter_excluded_files(logo_data: List[Dict]) -> List[Dict]:
    """Filter out excluded navigation/UI files."""
    filtered = []
    for item in logo_data:
        filename = Path(item['imageUrl']).name.split('?')[0]
        if filename not in EXCLUDE_FILES:
            filtered.append(item)
    return filtered


def load_inventory(inventory_path: Path) -> List[Dict]:
    """Load existing inventory from JSON file."""
    if not inventory_path.exists():
        return []

    try:
        with open(inventory_path, 'r', encoding='utf-8') as f:
            inventory = json.load(f)
        print(f'Loaded existing inventory with {len(inventory)} entries')
        return inventory
    except Exception as e:
        print(f'Failed to load inventory: {e}', file=sys.stderr)
        return []


def save_inventory(inventory_path: Path, inventory: List[Dict], added_count: int) -> None:
    """Save inventory to JSON file, sorted by image filename (case-insensitive)."""
    try:
        # Sort inventory by image field (case-insensitive)
        sorted_inventory = sorted(inventory, key=lambda x: x['image'].lower())

        with open(inventory_path, 'w', encoding='utf-8') as f:
            json.dump(sorted_inventory, f, indent=2, ensure_ascii=False)
        print(f'\nSaved inventory with {len(inventory)} entries ({added_count} new) to {inventory_path}')
    except Exception as e:
        print(f'Failed to save inventory: {e}', file=sys.stderr)


async def main():
    """Main scraping function."""
    # Parse command-line arguments
    impl_type = sys.argv[1] if len(sys.argv) > 1 else 'consumer'

    if impl_type not in ('consumer', 'workforce'):
        print('Invalid implementation type. Use "consumer" or "workforce"', file=sys.stderr)
        sys.exit(1)

    print('Launching browser...')
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        try:
            print(f'Navigating to {TARGET_URL}...')
            # Use 'load' instead of 'networkidle' - Playwright's networkidle is stricter than Puppeteer's networkidle2
            # and can timeout on pages with persistent background requests
            await page.goto(TARGET_URL, wait_until='load')
            await asyncio.sleep(2)

            # Validate page structure
            print('Validating page structure...')
            validation = await validate_page_structure(page)

            if validation['errors']:
                print('\n⚠️  WARNING: Page structure validation failed!', file=sys.stderr)
                print('The webpage may have changed significantly.', file=sys.stderr)
                print('\nValidation results:', file=sys.stderr)
                print(f"  - Consumer checkbox: {'✓' if validation['hasConsumerCheckbox'] else '✗'}", file=sys.stderr)
                print(f"  - Workforce checkbox: {'✓' if validation['hasWorkforceCheckbox'] else '✗'}", file=sys.stderr)
                print(f"  - Load all button: {'✓' if validation['hasLoadButton'] else '✗'}", file=sys.stderr)
                print(f"  - Expected title/heading: {'✓' if validation['hasExpectedTitle'] else '✗'}", file=sys.stderr)
                print('\nErrors detected:', file=sys.stderr)
                for error in validation['errors']:
                    print(f'  - {error}', file=sys.stderr)
                print('\nAborting script to prevent incorrect scraping.', file=sys.stderr)
                sys.exit(1)

            print(f"Page validation passed")

            # Click implementation type checkbox
            await click_implementation_checkbox(page, impl_type)
            await asyncio.sleep(1)

            # Click load all button
            await click_load_all(page)

            # Extract logo data
            print('Extracting logo URLs...')
            logo_data = await extract_logo_data(page)

            # Filter excluded files
            filtered_data = filter_excluded_files(logo_data)
            excluded_count = len(logo_data) - len(filtered_data)

            print(f'Found {len(filtered_data)} logo entries ({excluded_count} excluded)')

            if not filtered_data:
                print('No logos found. Page structure:', file=sys.stderr)
                body_html = await page.evaluate('() => document.body.innerHTML.substring(0, 1000)')
                print(body_html, file=sys.stderr)
                return

            # Load existing inventory
            OUTPUT_DIR.mkdir(exist_ok=True)
            IMAGES_DIR.mkdir(exist_ok=True)
            inventory_path = OUTPUT_DIR / INVENTORY_FILE
            inventory = load_inventory(inventory_path)

            # Create map of existing inventory entries
            inventory_map = {entry['image']: entry for entry in inventory}

            # Download logos
            downloaded_count = 0
            skipped_count = 0
            inventory_added_count = 0
            processed_count = 0

            # Create HTTP session for downloads
            async with aiohttp.ClientSession() as session:
                for i, item in enumerate(filtered_data, 1):
                    url = item['imageUrl']
                    filename = get_filename_from_url(url)
                    output_path = IMAGES_DIR / filename

                    processed_count += 1

                    # Check if file exists
                    if output_path.exists():
                        print(f'Skipping [{i}/{len(filtered_data)}]: {filename} (already exists)')
                        skipped_count += 1
                    else:
                        try:
                            print(f'Downloading [{i}/{len(filtered_data)}]: {filename}')
                            await download_image(session, url, output_path)
                            downloaded_count += 1
                        except Exception as e:
                            print(f'  Failed to download {url}: {e}', file=sys.stderr)
                            continue

                    # Add to inventory if not present (whether file was downloaded or already existed)
                    if filename not in inventory_map:
                        entry = {
                            'image': filename,
                            'learn_more_url': item['learnMoreUrl'],
                            'implementation_type': impl_type,
                            'company': None,
                            'frontpage_url': None,
                        }
                        inventory.append(entry)
                        inventory_map[filename] = entry
                        inventory_added_count += 1

            # Save inventory
            save_inventory(inventory_path, inventory, inventory_added_count)

            print(f'Done! Downloaded {downloaded_count} new logos, skipped {skipped_count} existing logos')
            print(f'Total logos processed: {processed_count}')

        finally:
            await browser.close()


if __name__ == '__main__':
    asyncio.run(main())
