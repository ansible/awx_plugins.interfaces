# pylint: disable=fixme
"""Shared stubs from ``awx`` managed credential type.

The hope is that it will be refactored into something more standardized.
"""

from typing import Protocol


try:
    # pylint: disable-next=unused-import
    from awx.main.models.credential import (  # noqa: WPS433
        ManagedCredentialType as ManagedCredentialType,
    )
except ImportError:  # FIXME: eventually, this should not exist
    from dataclasses import dataclass  # noqa: WPS433

    @dataclass(frozen=True)
    class ManagedCredentialType:  # type: ignore[no-redef]  # noqa: WPS440
        """Managed credential type stub."""

        namespace: str
        """Plugin namespace."""

        name: str
        """Plugin name within the namespace."""

        kind: str
        """Plugin category."""

        inputs: dict[str, list[dict[str, bool | str] | str]]
        """UI input fields schema."""

        injectors: dict[str, dict[str, str]] | None = None
        """Injector hook parameters."""

        managed: bool = False
        """Flag for whether this plugin instance is managed."""


class _CredentialInput(Protocol):
    def get_input(
        self: '_CredentialInput',
        name: str,
        default: object = None,
    ) -> bool | str:
        """Get an input from this credential.

        :param name: Input name to check.
        :type name: str
        :param default: Fallback for a missing input.
        :type default: object
        """

    def has_input(self: '_CredentialInput', name: str) -> bool:
        """Check if an input is present.

        :param name: Input name to check.
        :type name: str
        """


def _retrieve_openstack_data_from_credential(  # noqa: WPS234, WPS320
        cred: _CredentialInput,
) -> dict[
    str,
    dict[str, dict[str, dict[str, bool | str] | bool | str]],  # noqa: WPS221
]:
    openstack_auth = {
        'auth_url': cred.get_input('host', default=''),
        'username': cred.get_input('username', default=''),
        'password': cred.get_input('password', default=''),
        'project_name': cred.get_input('project', default=''),
    }
    if cred.has_input('project_domain_name'):
        openstack_auth['project_domain_name'] = cred.get_input(
            'project_domain_name', default='',
        )
    if cred.has_input('domain'):
        openstack_auth['domain_name'] = cred.get_input('domain', default='')
    verify_state = cred.get_input('verify_ssl', default=True)

    openstack_data = {
        'clouds': {
            'devstack': {
                'auth': openstack_auth,
                'verify': verify_state,
            },
        },
    }

    if cred.has_input('region'):
        openstack_data['clouds']['devstack']['region_name'] = cred.get_input(
            'region', default='',
        )

    return openstack_data


__all__ = ()  # noqa: WPS410
