import requests
import pytest
from ..conftest import APP_DOMAIN

INTERNETNL_API = f"https://{APP_DOMAIN}/api/batch/v2/"


@pytest.mark.parametrize(
    "path",
    ["requests", "requests/414878c6bde74343bcbf6a14de7d62de", "requests/414878c6bde74343bcbf6a14de7d62de/results"],
)
def test_batch_requires_auth(path):
    """Batch API endpoints should be behind authentication even when batch is not enabled."""
    response = requests.post(INTERNETNL_API + path, json={}, verify=False)
    assert response.status_code == 401
