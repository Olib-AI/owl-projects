"""Pytest fixtures for AutoQA tests."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test artifacts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_test_spec() -> str:
    """Sample test specification YAML."""
    return '''
name: Sample Login Test
description: Test user login functionality
metadata:
  tags:
    - smoke
    - auth
  priority: high
  owner: qa-team

variables:
  base_url: https://example.com
  username: testuser

steps:
  - name: Navigate to login page
    action: navigate
    url: ${base_url}/login
    wait_until: networkidle

  - name: Enter username
    action: type
    selector: "#username"
    text: ${username}

  - name: Enter password
    action: type
    selector: "#password"
    text: ${env:TEST_PASSWORD}

  - name: Click login button
    action: click
    selector: "button[type='submit']"

  - name: Verify dashboard
    action: assert
    assertion:
      selector: ".dashboard"
      operator: is_visible
      message: Dashboard should be visible after login
'''


@pytest.fixture
def sample_test_suite() -> str:
    """Sample test suite YAML."""
    return '''
name: E2E Test Suite
description: End-to-end test suite
metadata:
  tags:
    - e2e
  priority: critical

parallel_execution: true
max_parallel: 3
fail_fast: false

tests:
  - name: Homepage Test
    steps:
      - name: Navigate to homepage
        action: navigate
        url: https://example.com

      - name: Verify title
        action: assert
        assertion:
          selector: h1
          operator: contains
          expected: Welcome

  - name: About Page Test
    steps:
      - name: Navigate to about
        action: navigate
        url: https://example.com/about

      - name: Verify content
        action: assert
        assertion:
          selector: ".about-content"
          operator: exists
'''


@pytest.fixture
def mock_browser() -> MagicMock:
    """Create a mock OwlBrowser instance (SDK v2)."""
    import asyncio

    browser = MagicMock()

    # SDK v2: create_context returns a dict with context_id
    async def mock_create_context():
        return {"context_id": "test-ctx-001"}

    browser.create_context = MagicMock(side_effect=mock_create_context)
    browser.close_context = MagicMock(return_value=asyncio.coroutine(lambda **kw: None)())

    # SDK v2: all methods are async and take context_id
    browser.navigate = MagicMock(return_value=asyncio.coroutine(lambda **kw: None)())
    browser.click = MagicMock(return_value=asyncio.coroutine(lambda **kw: None)())
    browser.type = MagicMock(return_value=asyncio.coroutine(lambda **kw: None)())
    browser.is_visible = MagicMock(return_value=asyncio.coroutine(lambda **kw: {"success": True})())
    browser.is_enabled = MagicMock(return_value=asyncio.coroutine(lambda **kw: {"success": True})())
    browser.extract_text = MagicMock(return_value=asyncio.coroutine(lambda **kw: {"text": "Sample text"})())
    browser.screenshot = MagicMock(return_value=asyncio.coroutine(lambda **kw: {"data": ""})())
    browser.get_network_log = MagicMock(return_value=asyncio.coroutine(lambda **kw: {"entries": []})())
    browser.get_console_log = MagicMock(return_value=asyncio.coroutine(lambda **kw: [])())
    browser.wait_for_selector = MagicMock(return_value=asyncio.coroutine(lambda **kw: None)())
    browser.wait_for_network_idle = MagicMock(return_value=asyncio.coroutine(lambda **kw: None)())
    browser.evaluate = MagicMock(return_value=asyncio.coroutine(lambda **kw: None)())
    browser.get_page_info = MagicMock(return_value=asyncio.coroutine(lambda **kw: {"url": "https://example.com"})())

    return browser
