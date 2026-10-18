"""Run with RUN_BROWSER_TESTS=1 and Playwright Chromium installed."""

import os
from pathlib import Path
from urllib.parse import urlsplit

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_BROWSER_TESTS") != "1", reason="Opt-in browser tests"
)


def test_admin_editor_and_mobile_submission(db, monkeypatch):
    from playwright.sync_api import expect, sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(viewport={"width": 1280, "height": 1000})

        def handle(route):
            req = route.request
            url = urlsplit(req.url)
            if url.hostname not in ("testserver", "canvasser.test"):
                route.abort()
                return
            client = db.canvasser if url.hostname == "canvasser.test" else db.admin
            headers = {
                k: v
                for k, v in req.headers.items()
                if k not in ("host", "cookie", "origin", "content-length")
            }
            headers["origin"] = "https://testserver"
            response = client.request(
                req.method,
                url.path + ("?" + url.query if url.query else ""),
                content=req.post_data_buffer,
                headers=headers,
            )
            route.fulfill(
                status=response.status_code,
                headers=dict(response.headers),
                body=response.content,
            )

        context.route("**/*", handle)
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        from app.common import email_auth

        inbox = []
        monkeypatch.setattr(
            email_auth, "send_code", lambda email, code, purpose: inbox.append(code)
        )
        db.admin.cookies.clear()
        Path("docs/screenshots").mkdir(parents=True, exist_ok=True)
        page.goto("https://testserver/admin/login")
        page.screenshot(path="docs/screenshots/sign-in.png", full_page=True)
        page.get_by_label("Email address", exact=True).fill("admin@example.test")
        page.get_by_role("button", name="Email me a sign-in code", exact=True).click()
        expect(page.get_by_label("6-digit sign-in code", exact=True)).to_be_visible()
        page.get_by_label("6-digit sign-in code", exact=True).fill(inbox[-1])
        page.get_by_role("button", name="Sign in", exact=True).click()
        expect(
            page.get_by_role("link", name="Manage survey questions →")
        ).to_be_visible()
        page.screenshot(path="docs/screenshots/admin-dashboard.png", full_page=True)
        page.get_by_label("Route ID", exact=True).last.fill("test-route")
        page.get_by_role("button", name="Show addresses", exact=True).click()
        expect(page.locator("#addressesTableBody")).to_contain_text("Example Street")
        page.get_by_label("Route ID (optional)", exact=True).fill("test-route")
        expect(
            page.locator('[data-export="/admin/answers/export.csv"]')
        ).to_have_attribute("href", "/admin/answers/export.csv?route_id=test-route")
        for width in [320, 390]:
            page.set_viewport_size({"width": width, "height": 844})
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.get_by_role("link", name="Manage survey questions →").click()
        expect(page.get_by_text("No questions yet.", exact=False)).to_be_visible()
        page.get_by_label("Question", exact=True).fill("What matters to you locally?")
        page.get_by_label("Answer type").select_option("single_choice")
        page.get_by_label("Answer choices").fill("Parks\nTransport")
        page.get_by_label("Require an answer").check()
        page.get_by_role("button", name="Add question", exact=True).click()
        expect(page.get_by_text("Question added.", exact=True)).to_be_visible()
        page.get_by_role("button", name="Edit", exact=True).click()
        page.get_by_label("Question", exact=True).fill(
            "What should we improve locally?"
        )
        page.get_by_role("button", name="Save changes", exact=True).click()
        expect(page.get_by_text("Question updated.", exact=True)).to_be_visible()
        page.get_by_role("button", name="Edit", exact=True).click()
        page.get_by_role("link", name="+ Add a question", exact=True).click()
        expect(page.get_by_label("Question", exact=True)).to_have_value("")
        expect(
            page.get_by_role("button", name="Add question", exact=True)
        ).to_be_visible()
        page.get_by_role("button", name="Remove", exact=True).click()
        page.get_by_role("button", name="Remove question", exact=True).click()
        expect(page.get_by_text("Question removed.", exact=False)).to_be_visible()
        page.locator("summary").click()
        page.get_by_role("button", name="Restore", exact=True).click()
        expect(page.get_by_text("Question restored.", exact=True)).to_be_visible()
        Path("docs/screenshots").mkdir(parents=True, exist_ok=True)
        page.screenshot(path="docs/screenshots/survey-builder.png", full_page=True)
        page.set_viewport_size({"width": 390, "height": 844})
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        page.goto("https://canvasser.test/r/test-route")
        expect(
            page.get_by_text("What should we improve locally? (required)", exact=True)
        ).to_be_visible()
        page.locator("#addrSelect").select_option(label="Example Street")
        page.locator("#houseSelect").select_option(index=1)
        page.locator("#unitSelect").select_option("1")
        page.locator("#personSelect").select_option(index=1)
        expect(page.locator("#visitContext")).to_contain_text("Example Street")
        expect(page.locator("#submitBtn")).to_be_disabled()
        expect(page.locator("#saveHeading")).to_have_text("Answer 1 required question")
        page.get_by_label("Parks", exact=True).check()
        expect(page.locator("#submitBtn")).to_be_enabled()
        page.screenshot(path="docs/screenshots/canvasser-mobile.png", full_page=True)
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        page.set_viewport_size({"width": 1280, "height": 1000})
        page.screenshot(path="docs/screenshots/canvasser-desktop.png", full_page=True)
        page.set_viewport_size({"width": 390, "height": 844})
        page.locator("#submitBtn").click()
        expect(page.locator("#submitMsg")).to_have_text("Saved.")
        assert not errors, errors
        browser.close()
