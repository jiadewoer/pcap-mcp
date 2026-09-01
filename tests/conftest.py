from __future__ import annotations

import pytest

from pcap_mcp import config


@pytest.fixture(autouse=True)
def clear_settings_cache():
    config.reset_settings()
    yield
    config.reset_settings()
