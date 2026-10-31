import pytest
from fastapi.testclient import TestClient

from web_decoy.app import create_app
from web_decoy.config import Settings

LAB_IP = "127.0.0.1"          # inside default HEALTH_ALLOWED_CIDRS
OUTSIDE_IP = "203.0.113.10"   # TEST-NET-3, outside every allowlist

GOOD_USER = "j.miller"
GOOD_PASS = "Halden#Spring26"


@pytest.fixture
def settings():
    return Settings()


@pytest.fixture
def app(settings):
    return create_app(settings)


def _client(app, ip):
    return TestClient(app, client=(ip, 40000), follow_redirects=False)


@pytest.fixture
def client(app):
    """An attacker-like client outside every allowlist."""
    return _client(app, OUTSIDE_IP)


@pytest.fixture
def lab_client(app):
    return _client(app, LAB_IP)


@pytest.fixture
def logged_in(client):
    r = client.post("/login", data={"username": GOOD_USER, "password": GOOD_PASS})
    assert r.status_code == 302
    return client
