# pylint: disable=fixme
"""Shared stubs from ``awx`` managed credential type.

The hope is that it will be refactored into something more standardized.
"""

import typing as _t
from collections.abc import Callable, Mapping

from ._temporary_private_credential_api import (  # noqa: WPS436
    Credential as Credential,
)


InputDefinitionValueType = list[dict[str, str | bool]]
InputDefinitionType = dict[str, InputDefinitionValueType]

InjectorDefinitionBaseType = dict[str, dict[str, str]]
InjectorDefinitionType = _t.Union[InjectorDefinitionBaseType, None]

EnvVarsValueType = Mapping[str, 'EnvVarsType'] | list['EnvVarsType'] | str
EnvVarsType = dict[str, EnvVarsValueType]

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

        inputs: InputDefinitionType
        """UI input fields schema."""

        injectors: InjectorDefinitionType = None
        """Injector hook parameters."""

        managed: bool = False
        """Flag for whether this plugin instance is managed."""

        custom_injectors: (
            Callable[
                [
                    Credential,
                    EnvVarsType,
                    str,
                ],
                str | None,
            ]
            | None
        ) = None
        """Function to call as an alternative to the templated injection."""


__all__ = ()  # noqa: WPS410
