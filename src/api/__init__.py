"""ZK Travel Rule Compliance Bridge — REST API package."""


def create_app():
    """Import routes only when constructing an app, avoiding auth import cycles."""
    from src.api.main import create_app as factory

    return factory()


__all__ = ["create_app"]
