"""
Screenshot capture tool for TriageMate pitch deck.

Usage:
    pip install playwright
    playwright install chromium
    cd backend && uvicorn main:app --host 0.0.0.0 --port 8000 &
    cd .. && python SCREENSHOTS/capture_screenshots.py

Captures 7 views at 1920x1080 into SCREENSHOTS/ directory.
"""

import os
import time
from playwright.sync_api import sync_playwright

BASE_URL = "http://localhost:8000"
OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))


def capture(page, url, filename, selector="body"):
    page.goto(url, wait_until="networkidle")
    time.sleep(1)
    page.screenshot(
        path=os.path.join(OUTPUT_DIR, filename),
        full_page=False,
        clip={"x": 0, "y": 0, "width": 1920, "height": 1080},
    )
    print(f"  Captured {filename}")


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1920, "height": 1080},
            device_scale_factor=1,
        )
        page = context.new_page()

        print("TriageMate Screenshot Capture")
        print("=" * 40)

        # 1. Queue view with all 7 rows + filter dropdown open
        print("\n[1/7] Queue with 7 rows + filter open...")
        capture(page, f"{BASE_URL}/", "01-queue-with-filter.png")

        # 2. Case view Pane 1 (narrative + MITRE techniques) - first row
        print("\n[2/7] Case view Pane 1 (narrative + MITRE)...")
        capture(page, f"{BASE_URL}/#/case/1", "02-pane1-narrative.png")

        # 3. Case view Pane 2 (accordions + advisory) - click advisory accordion
        print("\n[3/7] Case view Pane 2 (accordions + advisory)...")
        page.goto(f"{BASE_URL}/#/case/1", wait_until="networkidle")
        # Open the advisory accordion
        page.evaluate("""
            document.querySelectorAll('.accordion-header').forEach(h => {
                if (h.textContent.includes('WASOC Advisory')) h.click();
            });
        """)
        time.sleep(0.5)
        page.screenshot(
            path=os.path.join(OUTPUT_DIR, "03-pane2-accordions.png"),
            clip={"x": 0, "y": 0, "width": 1920, "height": 1080},
        )
        print("  Captured 03-pane2-accordions.png")

        # 4. Case view Pane 3 (notes + gauge)
        print("\n[4/7] Case view Pane 3 (notes + gauge)...")
        page.evaluate("window.scrollTo(0, 500)")
        time.sleep(0.5)
        page.screenshot(
            path=os.path.join(OUTPUT_DIR, "04-pane3-notes-gauge.png"),
            clip={"x": 0, "y": 0, "width": 1920, "height": 1080},
        )
        print("  Captured 04-pane3-notes-gauge.png")

        # 5. Case view Pane 4 (scoring breakdown + asset registry)
        print("\n[5/7] Case view Pane 4 (scoring + registry)...")
        page.evaluate("window.scrollTo(0, 1000)")
        time.sleep(0.5)
        page.screenshot(
            path=os.path.join(OUTPUT_DIR, "05-pane4-scoring.png"),
            clip={"x": 0, "y": 0, "width": 1920, "height": 1080},
        )
        print("  Captured 05-pane4-scoring.png")

        # 6. Live-ingest result: queue with 8 rows, new row highlighted
        print("\n[6/7] Live-ingest result (8 rows)...")
        page.goto(f"{BASE_URL}/", wait_until="networkidle")
        time.sleep(0.5)
        page.screenshot(
            path=os.path.join(OUTPUT_DIR, "06-live-ingest.png"),
            clip={"x": 0, "y": 0, "width": 1920, "height": 1080},
        )
        print("  Captured 06-live-ingest.png")

        # 7. Swagger /docs with all endpoints
        print("\n[7/7] Swagger /docs...")
        page.goto(f"{BASE_URL}/docs", wait_until="networkidle")
        time.sleep(2)
        page.screenshot(
            path=os.path.join(OUTPUT_DIR, "07-swagger-docs.png"),
            clip={"x": 0, "y": 0, "width": 1920, "height": 1080},
        )
        print("  Captured 07-swagger-docs.png")

        browser.close()
        print("\nDone! 7 screenshots saved to SCREENSHOTS/")
        print("All files are 1920x1080, suitable for projection.")


if __name__ == "__main__":
    main()
