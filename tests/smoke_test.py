"""This module exists to validate that the skeleton is functional.

It can be deleted once the project has actual tests in.
"""

from awx_plugins.interfaces import api


def test_smoke() -> None:
    """Ensure the CI picks this up."""
    assert f'that {api} works'
