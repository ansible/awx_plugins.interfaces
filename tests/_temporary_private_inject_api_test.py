"""Tests for injector interface."""

import os
import shutil
import tempfile
from collections.abc import Generator
from pathlib import Path

# NOTE: The unittest import should not be here but we temporarily have it until
# NOTE: it's replaced with the `pytest-mock`'s `mocker` fixture.
from unittest import mock  # pylint: disable=deprecated-module,preferred-module

import pytest

import jinja2
from yaml import safe_load as yaml_safe_load

from awx_plugins.interfaces._temporary_private_api import (
    EnvVarsType,
    InjectorDefinitionType,
    InputDefinitionType,
    ManagedCredentialType,
)
from awx_plugins.interfaces._temporary_private_container_api import (
    CONTAINER_ROOT,
)
from awx_plugins.interfaces._temporary_private_credential_api import (
    Credential,
    CredentialInputType,
)
from awx_plugins.interfaces._temporary_private_inject_api import (
    HIDDEN_PASSWORD,
    ArgsType,
    inject_credential,
)


# pylint: disable=redefined-outer-name
def to_host_path(path: str, private_data_dir: str) -> str:
    """Convert container path to host path.

    Given a path inside of the EE container, this gives the absolute
    path on the host machine within the private_data_dir.

    :param path: container path
    :param private_data_dir: runtime directory
    :raises ValueError: When private_data_dir is not an absolute path
    :raises ValueError: path must be a subdir of the container root dir
    :return: Absolute path of private_data_dir on the container host
    """
    if not os.path.isabs(private_data_dir):
        raise ValueError('The private_data_dir path must be absolute')
    is_subdir_of_container = (
        CONTAINER_ROOT == path
        or Path(CONTAINER_ROOT) in Path(path).resolve().parents
    )
    if not is_subdir_of_container:
        raise ValueError(
            f'Cannot convert path {path}, not a subdir of {CONTAINER_ROOT}',
        )
    return path.replace(CONTAINER_ROOT, private_data_dir, 1)


@pytest.fixture
def private_data_dir() -> Generator[str, None, None]:
    """Simulate ansible-runner directory backed runtime parameters.

    :yield: runtime directory
    """
    private_data = tempfile.mkdtemp(prefix='awx_')
    for subfolder in ('inventory', 'env'):
        runner_subfolder = os.path.join(private_data, subfolder)
        os.mkdir(runner_subfolder)
    yield private_data
    shutil.rmtree(private_data, ignore_errors=True)


def test_to_host_path_abs_path() -> None:
    """Check relative path results in an error."""
    with pytest.raises(ValueError, match='.*path must be absolute'):
        to_host_path('', 'is/not/absolute/')


def test_to_host_path_subdir() -> None:
    """Check path must be a subdir of the container dir."""
    with pytest.raises(ValueError, match='.* not a subdir .*'):
        to_host_path('not_a_subdir_of_CONTAINER_ROOT', '/is/absolute/')


@pytest.mark.parametrize(
    (
        'inputs',
        'injectors',
        'cred_inputs',
        'expected_env_vars',
    ),
    (
        pytest.param(
            {
                'fields': [
                    {
                        'id': 'my_field_name',
                        'label': 'My field name',
                        'type': 'string',
                    },
                ],
            },
            {'env': {'FIELD_NAME': '{{my_field_name}}'}},
            {'my_field_name': 'just_another_value'},
            {'FIELD_NAME': 'just_another_value'},
            id='fields-env',
        ),
        pytest.param(
            {
                'fields': [
                    {
                        'id': 'my_var',
                        'label': 'My var name',
                        'type': 'string',
                    },
                ],
            },
            {'env': {'VAR_NAME': '{{my_var}}'}},
            {'var_name': ''},
            {'VAR_NAME': ''},
            id='fields-env-missing-input',
        ),
        pytest.param(
            {
                'fields': [
                    {
                        'id': 'my_ssh_key',
                        'label': 'My ssh key',
                        'type': 'string',
                        'format': 'ssh_private_key',
                    },
                ],
            },
            {'env': {'MY_SSH_KEY': '{{my_ssh_key}}'}},
            {'my_ssh_key': 'super_secret'},
            {'MY_SSH_KEY': 'super_secret\n'},
            id='field-format-ssh-private-key-add-newline',
        ),
        pytest.param(
            {
                'fields': [
                    {
                        'id': 'my_rsa_key',
                        'label': 'My rsa key',
                        'type': 'string',
                        'format': 'ssh_private_key',
                    },
                ],
            },
            {'env': {'RSA_THING': '{{my_rsa_key}}'}},
            {'my_rsa_key': 'secret_rsa_key\n'},
            {'RSA_THING': 'secret_rsa_key\n'},
            id='field-format-ssh-private-key-do-not-add-newline',
        ),
        pytest.param(
            {
                'fields': [
                    {
                        'id': 'api_oauth_token',
                        'label': 'API Oauth Token',
                        'type': 'string',
                    },
                ],
            },
            {'env': {'JOB_ID': 'reserved'}},
            {'api_oauth_token': 'ABC789'},
            {},
            id='reserved-env-var',
        ),
    ),
)
def test_injectors_with_env_vars(
    inputs: InputDefinitionType,
    injectors: InjectorDefinitionType,
    cred_inputs: CredentialInputType,
    expected_env_vars: dict[str, str],
) -> None:
    """Check basic env var injection."""
    cred_type = ManagedCredentialType(
        namespace='animal',
        name='dog',
        kind='companion',
        managed=True,
        inputs=inputs,
        injectors=injectors,
    )
    cred = Credential(inputs=cred_inputs)

    env: EnvVarsType = {}
    inject_credential(cred_type, cred, env, {}, [], '')

    assert expected_env_vars.items() == env.items()


def test_injectors_with_jinja_syntax_error(
    private_data_dir: str,
) -> None:
    """Check malicious jinja is not allowed."""
    cred_type = ManagedCredentialType(
        kind='cloudx',
        name='SomeCloudy',
        namespace='foo',
        managed=False,
        inputs={
            'fields': [
                {'id': 'api_oauth', 'label': 'API Token', 'type': 'string'},
            ],
        },
        injectors={'env': {'MY_CLOUD_OAUTH': '{{api_oauth.foo()}}'}},
    )
    credential = Credential(inputs={'api_oauth': 'ABC123'})

    with pytest.raises(jinja2.exceptions.UndefinedError):
        inject_credential(cred_type, credential, {}, {}, [], private_data_dir)


def test_injectors_with_secret_field(private_data_dir: str) -> None:
    """Check that secret values are obscured."""
    cred_type = ManagedCredentialType(
        kind='clouda',
        name='SomeCloudb',
        namespace='foo',
        managed=False,
        inputs={
            'fields': [
                {
                    'id': 'password',
                    'label': 'Password',
                    'type': 'string',
                    'secret': True,
                },
            ],
        },
        injectors={'env': {'MY_CLOUD_PRIVATE_VAR': '{{password}}'}},
    )
    credential = Credential(inputs={'password': 'SUPER-SECRET-123'})

    env: EnvVarsType = {}
    safe_env: EnvVarsType = {}
    inject_credential(
        cred_type,
        credential,
        env,
        safe_env,
        [],
        private_data_dir,
    )

    assert env['MY_CLOUD_PRIVATE_VAR'] == 'SUPER-SECRET-123'
    assert 'SUPER-SECRET-123' not in safe_env.values()
    assert safe_env['MY_CLOUD_PRIVATE_VAR'] == HIDDEN_PASSWORD


@pytest.mark.parametrize(
    (
        'inputs',
        'injectors',
        'cred_inputs',
        'expected_extra_vars',
    ),
    (
        pytest.param(
            {
                'fields': [
                    {
                        'id': 'api_secret',
                        'label': 'API Secret',
                        'type': 'string',
                    },
                ],
            },
            {'extra_vars': {'api_secret': '{{api_secret}}'}},
            {'api_secret': 'ABC123'},
            {'api_secret': 'ABC123'},
            id='happy-path',
        ),
        pytest.param(
            {
                'fields': [
                    {
                        'id': 'turbo_button',
                        'label': 'Turbo Button',
                        'type': 'boolean',
                    },
                ],
            },
            {'extra_vars': {'turbo_button': '{{turbo_button}}'}},
            {'turbo_button': True},
            {'turbo_button': 'True'},
            id='boolean',
        ),
        pytest.param(
            {
                'fields': [
                    {
                        'id': 'host',
                        'label': 'Host',
                        'type': 'string',
                    },
                ],
            },
            {'extra_vars': {'auth': {'host': '{{host}}'}}},
            {'host': 'foo.example.com'},
            {'auth': {'host': 'foo.example.com'}},
            id='nested-dict',
        ),
        pytest.param(
            {
                'fields': [
                    {
                        'id': 'host',
                        'label': 'Host',
                        'type': 'string',
                    },
                ],
            },
            {
                'extra_vars': {
                    'auth': {
                        'host': [
                            '{{host_1}}',
                            '{{host_2}}',
                            '{{host_3}}',
                        ],
                    },
                },
            },
            {'host_1': 'a.com', 'host_2': 'b.com', 'host_3': 'c.com'},
            {'auth': {'host': ['a.com', 'b.com', 'c.com']}},
            id='nested-list',
        ),
        pytest.param(
            {
                'fields': [
                    {
                        'id': 'environment',
                        'label': 'Environment',
                        'type': 'string',
                    },
                    {
                        'id': 'host',
                        'label': 'Host',
                        'type': 'string',
                    },
                ],
            },
            {'extra_vars': {'{{environment}}_auth': {'host': '{{host}}'}}},
            {'environment': 'test', 'host': 'example.com'},
            {'test_auth': {'host': 'example.com'}},
            id='templated-key',
        ),
        pytest.param(
            {
                'fields': [
                    {
                        'id': 'trubo',
                        'label': 'Turbo Button',
                        'type': 'boolean',
                    },
                ],
            },
            {
                'extra_vars': {
                    'turbo': '{% if turbo %}FAST!{% else %}SLOW!{% endif %}',
                },
            },
            {'turbo': True},
            {'turbo': 'FAST!'},
            id='templated-bool',
        ),
    ),
)
def test_injectors_with_extra_vars(
    private_data_dir: str,
    inputs: InputDefinitionType,
    injectors: InjectorDefinitionType,
    cred_inputs: CredentialInputType,
    expected_extra_vars: dict[str, str],
) -> None:
    """Check extra vars are injected in a file."""
    cred_type = ManagedCredentialType(
        kind='cloudc',
        name='SomeCloudd',
        namespace='foo',
        managed=False,
        inputs=inputs,
        injectors=injectors,
    )
    credential = Credential(inputs=cred_inputs)

    args: ArgsType = []
    inject_credential(cred_type, credential, {}, {}, args, private_data_dir)
    extra_vars_fname = to_host_path(args[1][1:], private_data_dir)
    with open(extra_vars_fname, encoding='utf-8') as extra_vars_file:
        extra_vars = yaml_safe_load(extra_vars_file)

    assert expected_extra_vars.items() <= extra_vars.items()


def test_injectors_inv_update_id(private_data_dir: str) -> None:
    """Check that extra vars are not injected for an inventory update."""
    cred_type = ManagedCredentialType(
        namespace='animal',
        name='dog',
        kind='companion',
        managed=True,
        inputs={},
        injectors={'extra_vars': {'do-not-inject': 'should-not-inject'}},
    )
    args: ArgsType = []
    inject_credential(
        cred_type,
        Credential(inputs={}),
        {'INVENTORY_UPDATE_ID': '1'},
        {},
        args,
        private_data_dir,
    )

    assert not args


@pytest.mark.parametrize(
    (
        'inputs',
        'injectors',
        'cred_inputs',
        'expected_file_content',
    ),
    (
        pytest.param(
            {
                'fields': [
                    {
                        'id': 'api_token',
                        'label': 'API Token',
                        'type': 'string',
                    },
                ],
            },
            {
                'file': {'template': '[mycloud]\n{{api_token}}'},
                'env': {'MY_CLOUD_INI_FILE': '{{tower.filename}}'},
            },
            {'api_token': 'ABC456'},
            {
                'MY_CLOUD_INI_FILE': '[mycloud]\nABC456',
            },
            id='ini-file',
        ),
        pytest.param(
            {'fields': []},
            {
                'file': {'template': 'Iñtërnâtiônàlizætiøn'},
                'env': {'MY_PERSONAL_INI_FILE': '{{tower.filename}}'},
            },
            {},
            {
                'MY_PERSONAL_INI_FILE': 'Iñtërnâtiônàlizætiøn',
            },
            id='unicode',
        ),
        pytest.param(
            {
                'fields': [
                    {
                        'id': 'cert',
                        'label': 'Certificate',
                        'type': 'string',
                    },
                    {
                        'id': 'key',
                        'label': 'Key',
                        'type': 'string',
                    },
                ],
            },
            {
                'file': {
                    'template.cert': '[mycert]\n{{cert}}',
                    'template.key': '[mykey]\n{{key}}',
                },
                'env': {
                    'MY_CERT_INI_FILE': '{{tower.filename.cert}}',
                    'MY_KEY_INI_FILE': '{{tower.filename.key}}',
                },
            },
            {
                'cert': 'CERT123',
                'key': 'KEY123',
            },
            {
                'MY_CERT_INI_FILE': '[mycert]\nCERT123',
                'MY_KEY_INI_FILE': '[mykey]\nKEY123',
            },
            id='multiple-files',
        ),
    ),
)
def test_injectors_with_file(
    private_data_dir: str,
    inputs: InputDefinitionType,
    injectors: InjectorDefinitionType,
    cred_inputs: CredentialInputType,
    expected_file_content: dict[str, str],
) -> None:
    """Check data flows from credential into a file."""
    cred_type = ManagedCredentialType(
        kind='cloude',
        name='SomeCloudf',
        namespace='foo',
        managed=False,
        inputs=inputs,
        injectors=injectors,
    )
    credential = Credential(inputs=cred_inputs)

    env: EnvVarsType = {}
    inject_credential(cred_type, credential, env, {}, [], private_data_dir)

    for env_fname_key, expected_content in expected_file_content.items():
        path = to_host_path(str(env[env_fname_key]), private_data_dir)
        with open(path, encoding='utf-8') as injected_file:
            assert injected_file.read() == expected_content


@pytest.mark.parametrize(
    'file_injectors',
    (
        pytest.param(
            {
                'template.ssh_keyfile': '{{ssh_key}}',
                'template.config_file': (
                    '[DEFAULT]\nkey_file={{tower.filename.ssh_keyfile}}'
                ),
            },
            id='config-references-keyfile',
        ),
        pytest.param(
            {
                'template.config_file': (
                    '[DEFAULT]\nkey_file={{tower.filename.ssh_keyfile}}'
                ),
                'template.ssh_keyfile': '{{ssh_key}}',
            },
            id='config-before-keyfile-in-dict',
        ),
    ),
)
def test_injectors_with_file_cross_reference(
    private_data_dir: str,
    file_injectors: dict[str, str],
) -> None:
    """Check that a file template can reference another file's path.

    This mirrors the OCI credential type pattern from AAP-78106 where
    a config file contains key_file={{ tower.filename.ssh_keyfile }}.
    Both dict orderings are tested to ensure the fix is order-independent.
    """
    cred_type = ManagedCredentialType(
        kind='cloudg',
        name='SomeCloudCrossRef',
        namespace='foo',
        managed=False,
        inputs={
            'fields': [
                {
                    'id': 'ssh_key',
                    'label': 'SSH Key',
                    'type': 'string',
                },
            ],
        },
        injectors={
            'file': file_injectors,
            'env': {
                'CONFIG_FILE': '{{tower.filename.config_file}}',
                'KEY_FILE': '{{tower.filename.ssh_keyfile}}',
            },
        },
    )
    credential = Credential(inputs={'ssh_key': 'PRIVATE_KEY_DATA'})

    env: EnvVarsType = {}
    inject_credential(cred_type, credential, env, {}, [], private_data_dir)

    key_file_path = str(env['KEY_FILE'])
    config_path = to_host_path(str(env['CONFIG_FILE']), private_data_dir)

    with open(config_path, encoding='utf-8') as config_file:
        config_content = config_file.read()

    assert key_file_path in config_content, (
        f'Config file should contain the key file path {key_file_path!r}, '
        f'got: {config_content!r}'
    )


def test_injectors_with_mixed_file_labels(
    private_data_dir: str,
) -> None:
    """Check that mixing bare 'template' and dotted 'template.<x>' raises.

    A credential type whose file injectors contain both ``template``
    (which sets ``tower.filename`` to a single path string) and
    ``template.<x>`` (which stores paths as ``tower.filename.<x>``)
    is ambiguous: the bare value would overwrite the namespace or vice-versa,
    silently breaking ``{{ tower.filename }}`` or ``{{ tower.filename.<x> }}``
    references in other injectors.
    """
    cred_type = ManagedCredentialType(
        kind='cloudy',
        name='MixedLabels',
        namespace='foo',
        managed=False,
        inputs={
            'fields': [
                {
                    'id': 'api_token',
                    'label': 'API Token',
                    'type': 'string',
                },
                {
                    'id': 'cert',
                    'label': 'Certificate',
                    'type': 'string',
                },
            ],
        },
        injectors={
            'file': {
                'template': '[mycloud]\n{{api_token}}',
                'template.cert': '{{cert}}',
            },
            'env': {
                'MY_CLOUD_INI_FILE': '{{tower.filename}}',
                'MY_CERT_FILE': '{{tower.filename.cert}}',
            },
        },
    )
    credential = Credential(
        inputs={'api_token': 'ABC456', 'cert': 'CERT_DATA'},
    )

    env: EnvVarsType = {}
    with pytest.raises(ValueError, match='cannot mix'):
        inject_credential(
            cred_type,
            credential,
            env,
            {},
            [],
            private_data_dir,
        )


@pytest.mark.parametrize(
    'managed',
    (True, False),  # noqa: WPS425
)
def test_custom_injectors(private_data_dir: str, managed: bool) -> None:
    """Check that custom injectors is used when defined."""
    injector = mock.Mock()
    cred_type = ManagedCredentialType(
        kind='cloudh',
        name='SomeCloudi',
        namespace='foo',
        managed=managed,
        inputs={'fields': []},
        custom_injectors=injector,
    )
    credential = Credential(inputs={})

    env: EnvVarsType = {}
    inject_credential(cred_type, credential, env, {}, [], private_data_dir)

    if managed:
        injector.assert_called_once()
    else:
        injector.assert_not_called()


@pytest.mark.parametrize(
    (
        'custom_injectors_env',
        'expected_safe_env',
    ),
    (
        pytest.param(
            {'foo': 'bar'},
            {'foo': 'bar'},
        ),
        pytest.param(
            {'MY_SPECIAL_TOKEN': 'foobar'},
            {'MY_SPECIAL_TOKEN': '**********'},
        ),
        pytest.param(
            {'ANSIBLE_MY_SPECIAL_TOKEN': 'foobar'},
            {'ANSIBLE_MY_SPECIAL_TOKEN': 'foobar'},
        ),
        pytest.param(
            {'FOO': 'https://my-username:my-password@foo.com'},
            {'FOO': '**********'},
        ),
    ),
)
def test_custom_injectors_safe_env(
    private_data_dir: str,
    custom_injectors_env: EnvVarsType,
    expected_safe_env: EnvVarsType,
) -> None:
    """Check that special env vars are obscured in safe env."""

    def custom_injectors(_cr: Credential, env: EnvVarsType, _pd: str) -> None:
        env |= custom_injectors_env

    cred_type = ManagedCredentialType(
        kind='cloud',
        name='SomeCloud',
        namespace='foo',
        managed=True,
        inputs={},
        custom_injectors=custom_injectors,
    )
    cred = Credential(inputs={})

    env: EnvVarsType = {}
    safe_env: EnvVarsType = {}
    inject_credential(
        cred_type,
        cred,
        env,
        safe_env,
        [],
        private_data_dir,
    )

    assert safe_env.items() == expected_safe_env.items()


@pytest.mark.parametrize(
    (
        'container_root',
        'expected_arg_prefix',
    ),
    (
        pytest.param(
            None,
            f'@{CONTAINER_ROOT}/',
            id='default-root',
        ),
        pytest.param(
            '/custom_root',
            '@/custom_root/',
            id='custom-root',
        ),
    ),
)
def test_custom_container_root_with_extra_vars(
    private_data_dir: str,
    container_root: str | None,
    expected_arg_prefix: str,
) -> None:
    """Check custom container root with extra vars."""
    cred_type = ManagedCredentialType(
        kind='cloudh',
        name='SomeCloudi',
        namespace='foo',
        managed=True,
        inputs={},
        injectors={'extra_vars': {'api_secret': '{{api_secret}}'}},
    )
    credential = Credential(inputs={})

    env: EnvVarsType = {}
    cmdline_args: list[str] = []
    inject_credential(
        cred_type,
        credential,
        env,
        {},
        cmdline_args,
        private_data_dir,
        container_root=container_root,
    )

    assert cmdline_args[0] == '-e'
    assert cmdline_args[1].startswith(expected_arg_prefix)
