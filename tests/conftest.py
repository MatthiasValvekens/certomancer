import pytest

from certomancer import crypto_utils

if crypto_utils.pyca_cryptography_present():
    backends = ["backend:oscrypto", "backend:cryptography"]
else:
    backends = ["backend:oscrypto"]


@pytest.fixture(scope="session", autouse=True, params=backends)
def crypto_backend(request):
    if 'oscrypto' in request.param:
        backend = crypto_utils.OscryptoBackend()
    else:
        backend = crypto_utils.PycaCryptographyBackend()
    # the monkeypatch fixture is function-scoped, so let's do it by hand
    orig_backend = crypto_utils.CRYPTO_BACKEND
    crypto_utils.CRYPTO_BACKEND = backend
    try:
        yield backend
    finally:
        crypto_utils.CRYPTO_BACKEND = orig_backend
