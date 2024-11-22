from typing import Callable


GenericOptionalPrimitiveType = bool | str | int | float | None


class Credential:
    def __init__(
        self,
        inputs: dict[str, GenericOptionalPrimitiveType] | None = None,
    ) -> None: ...

    def get_input(
            self,
            field_name: str,
            default: GenericOptionalPrimitiveType = None,
    ) -> GenericOptionalPrimitiveType: ...

    def has_input(self, field_name: str) -> bool: ...


class ManagedCredentialType:
    def __init__(
        self,
        namespace: str,
        name: str,
        kind: str,
        inputs: dict[str, list[dict[str, bool | str] | str]],
        injectors: dict[str, dict[str, str]] | None = None,
        managed: bool = False,
        custom_injector: Callable[[Credential, dict[str, GenericOptionalPrimitiveType], str], str | None] | None = None,
    ): ...
