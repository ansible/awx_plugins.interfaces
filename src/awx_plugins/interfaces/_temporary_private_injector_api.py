"""Shared tools for loading injectors."""

from collections.abc import Callable
from importlib.metadata import entry_points as _load_matching_entry_points
from os import PathLike
from typing import Protocol, cast


_INJECTOR_ENTRY_POINT_GROUP_NAME = 'awx_plugins.injector'


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


InjectorCallableType = Callable[
    [_CredentialInput, dict[str, str], PathLike[str] | str],
    None,
]


def load_injector_callable(injector_name: str, /) -> InjectorCallableType:
    """Load an injector discovered by name into runtime.

    :param injector_name: Entry-point key name under the
        "awx_plugins.injector" group in packaging metadata.
    :type injector_name: str
    :raises LookupError: When no distribution packages provide the
        requested entry-point name.
    :returns: An injector callable.
    :rtype: InjectorCallableType
    """
    injector_entry_points = _load_matching_entry_points(
        group=_INJECTOR_ENTRY_POINT_GROUP_NAME,
        name=injector_name,
    )
    if not injector_entry_points:
        raise LookupError

    injector_ep = injector_entry_points[injector_name]
    return cast(InjectorCallableType, injector_ep.load())


__all__ = ()  # noqa: WPS410
