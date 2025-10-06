from playwright.sync_api import sync_playwright, expect

def run(playwright):
    browser = playwright.chromium.launch()
    page = browser.new_page()

    # Go to the home page
    page.goto("http://127.0.0.1:5000/")

    # Take a screenshot of the home page
    page.screenshot(path="jules-scratch/verification/home_page.png")

    # Verify that the PDF/Images tab is visible
    expect(page.get_by_role("button", name="🧩 PDF e Imágenes")).to_be_visible()

    # Click on the Security tab
    page.get_by_role("button", name="🧰 Seguridad").click()

    # Verify that the SSL Check tool is visible
    expect(page.get_by_role("link", name="✅ SSL Check")).to_be_visible()

    # Click on the SSL Check tool
    page.get_by_role("link", name="✅ SSL Check").click()

    # Verify that the SSL Check page loads correctly
    expect(page.get_by_role("heading", name="✅ SSL Certificate Check")).to_be_visible()

    # Take a screenshot of the SSL Check page
    page.screenshot(path="jules-scratch/verification/ssl_check_page.png")

    browser.close()

with sync_playwright() as playwright:
    run(playwright)