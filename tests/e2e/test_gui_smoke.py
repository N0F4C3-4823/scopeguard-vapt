from __future__ import annotations

import csv
import json
import os
import tempfile
import zipfile
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.async_api")


@pytest.mark.asyncio
async def test_scopeguard_gui_fixture_lifecycle_and_exports():
    if os.getenv("SCOPEGUARD_E2E") != "1":
        pytest.skip("Set SCOPEGUARD_E2E=1 with a running ScopeGuard server to run the browser gate")
    async with playwright.async_playwright() as api:
        browser = await api.chromium.launch(
            headless=True,
            executable_path=os.getenv("SCOPEGUARD_CHROME", "/usr/bin/chromium"),
            args=["--no-sandbox"],
        )
        page = await browser.new_page(viewport={"width": 1440, "height": 1000}, accept_downloads=True)
        base_url = os.getenv("SCOPEGUARD_BASE_URL", "http://127.0.0.1:8001")
        await page.goto(base_url, wait_until="networkidle")
        assert await page.locator("#backend-health").inner_text() == "Backend healthy"
        await page.get_by_role("button", name="New assessment").first.click()
        assert await page.locator("#assessment-type option").count() == 4
        await page.locator("#assessment-name").fill("Automated guided fixture assessment")
        await page.locator('button[data-wizard-next="2"]').click()
        await page.locator("#targets").fill("fixture://mixed")
        await page.locator('button[data-wizard-next="3"]').click()
        await page.locator('button[data-select-type="external_unauthenticated"]').click()
        await page.locator('button[data-wizard-next="4"]').click()
        await page.locator("#authorization-note").fill("automated controlled fixture authorization")
        await page.locator("#authorized").check()
        # The lifecycle/export smoke test exercises the GUI and report path.
        # Local AI is validated by the live Ollama health/recovery gates;
        # disabling the optional secondary analysis here keeps the browser
        # gate bounded when the fixture intentionally emits many inconclusive
        # conditions.
        await page.locator("#llm-enabled").uncheck()
        await page.get_by_role("button", name="Create assessment").click()
        await page.locator('button[data-control="start"]').wait_for()
        await page.locator('button[data-control="start"]').click()
        await page.wait_for_function(
            "document.querySelector('.hero-status')?.textContent.trim() === 'COMPLETED'",
            timeout=60_000,
        )
        assert await page.get_by_text("40 rows").count() == 1
        await page.reload(wait_until="networkidle")
        assert await page.get_by_text("Assessment complete").count() == 1
        assert await page.get_by_text("40 rows").count() == 1
        await page.locator("#result-status").select_option("FOUND")
        assert await page.locator("#results-table tbody tr").count() > 0
        await page.locator("#result-status").select_option("all")
        await page.locator("button[data-preview]").first.click()
        await page.locator(".preview-image").wait_for()
        await page.locator(".modal-close").click()
        async with page.expect_download() as download_info:
            await page.get_by_role("link", name="Target CSV").click()
        csv_download = await download_info.value
        csv_path = Path(tempfile.gettempdir()) / "scopeguard-e2e.csv"
        await csv_download.save_as(csv_path)
        assert len(list(csv.DictReader(csv_path.read_text(encoding="utf-8").splitlines()))) == 40
        async with page.expect_download() as download_info:
            await page.get_by_role("link", name="Download complete report").click()
        zip_download = await download_info.value
        zip_path = Path(tempfile.gettempdir()) / "scopeguard-e2e.zip"
        await zip_download.save_as(zip_path)
        with zipfile.ZipFile(zip_path) as archive:
            assert archive.testzip() is None
            assert json.loads(archive.read("manifest.json"))["actual_rows"] == 40
            names = archive.namelist()
            assert any("/POCs/FOUND/" in name for name in names)
            assert any("/POCs/NOT_FOUND/" in name for name in names)
        await browser.close()


@pytest.mark.asyncio
async def test_scopeguard_gui_wizard_validation_and_system_navigation():
    if os.getenv("SCOPEGUARD_E2E") != "1":
        pytest.skip("Set SCOPEGUARD_E2E=1 with a running ScopeGuard server to run the browser gate")
    async with playwright.async_playwright() as api:
        browser = await api.chromium.launch(
            headless=True,
            executable_path=os.getenv("SCOPEGUARD_CHROME", "/usr/bin/chromium"),
            args=["--no-sandbox"],
        )
        page = await browser.new_page(viewport={"width": 1280, "height": 900})
        base_url = os.getenv("SCOPEGUARD_BASE_URL", "http://127.0.0.1:8001")
        await page.goto(base_url, wait_until="networkidle")
        await page.get_by_role("button", name="New assessment").first.click()
        await page.locator("#assessment-name").fill("Invalid target validation")
        await page.locator('button[data-wizard-next="2"]').click()
        await page.locator("#targets").fill("not a target")
        await page.locator('button[data-wizard-next="3"]').click()
        assert await page.get_by_role("alert").count() == 1
        assert "targets need attention" in (await page.get_by_role("alert").inner_text())
        await page.locator("#targets").fill("fixture://negative")
        await page.locator('button[data-wizard-next="3"]').click()
        await page.locator('button[data-select-type="internal_authenticated"]').click()
        assert await page.locator('button[data-select-type="internal_authenticated"].selected').count() == 1
        await page.get_by_role("button", name="Settings").click()
        await page.get_by_role("button", name="Tools & dependencies").click()
        await page.locator("h2", has_text="Adapter coverage").wait_for()
        assert await page.locator("h2", has_text="Adapter coverage").count() == 1
        await page.get_by_role("button", name="Settings").click()
        await page.get_by_role("button", name="Local AI status").click()
        await page.locator("h2", has_text="Runtime status").wait_for()
        assert await page.locator("h2", has_text="Runtime status").count() == 1
        await browser.close()
