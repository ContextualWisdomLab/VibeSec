from playwright.sync_api import sync_playwright

def run():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto("file:///app/scanner/dashboard/console.html")
        page.wait_for_timeout(1000)
        print("Page title:", page.title())
        browser.close()

run()
