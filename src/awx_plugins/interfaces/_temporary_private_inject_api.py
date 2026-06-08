"""Injectors exercise plugins."""

import os
import pathlib
import re
import stat
import tempfile
from collections.abc import Mapping
from types import SimpleNamespace

from jinja2.sandbox import ImmutableSandboxedEnvironment
from yaml import safe_dump as yaml_safe_dump

from awx_plugins.interfaces._temporary_private_container_api import (
    get_incontainer_path,
)

from ._temporary_private_api import EnvVarsType, ManagedCredentialType
from ._temporary_private_credential_api import (
    Credential,
    GenericOptionalPrimitiveType,
)


# pylint: disable-next=too-few-public-methods
class TowerNamespace(SimpleNamespace):
    """Dummy class."""

    filename: str | SimpleNamespace | None = None


TowerNamespaceValueType = TowerNamespace | GenericOptionalPrimitiveType
ExtraVarsType = Mapping[str, 'ExtraVarsType'] | list['ExtraVarsType'] | str

ArgsType = list[str]

HIDDEN_PASSWORD = '*' * 10
SENSITIVE_ENV_VAR_NAMES = 'API|TOKEN|KEY|SECRET|PASS'

HIDDEN_PASSWORD_RE = re.compile(SENSITIVE_ENV_VAR_NAMES, re.I)
HIDDEN_URL_PASSWORD_RE = re.compile('^.*?://[^:]+:(.*?)@.*?$')

ENV_BLOCKLIST = frozenset(
    (
        'VIRTUAL_ENV',
        'PATH',
        'PYTHONPATH',
        'JOB_ID',
        'INVENTORY_ID',
        'INVENTORY_SOURCE_ID',
        'INVENTORY_UPDATE_ID',
        'AD_HOC_COMMAND_ID',
        'REST_API_URL',
        'REST_API_TOKEN',
        'MAX_EVENT_RES',
        'CALLBACK_QUEUE',
        'CALLBACK_CONNECTION',
        'CACHE',
        'JOB_CALLBACK_DEBUG',
        'INVENTORY_HOSTVARS',
        'AWX_HOST',
        'PROJECT_REVISION',
        'SUPERVISOR_CONFIG_PATH',
    ),
)


def build_safe_env(
    env: EnvVarsType,
) -> EnvVarsType:
    """Obscure potentially sensitive environment values.

    Given a set of environment variables, execute a set of heuristics to
    obscure potentially sensitive environment values.

    :param env: Existing environment variables
    :returns: Sanitized environment variables.
    """
    safe_env = dict(env)
    for env_k, env_v in safe_env.items():
        is_special = env_k == 'AWS_ACCESS_KEY_ID' or (
            env_k.startswith('ANSIBLE_')
            and not env_k.startswith('ANSIBLE_NET')
            and not env_k.startswith('ANSIBLE_GALAXY_SERVER')
        )
        if is_special:
            continue
        if HIDDEN_PASSWORD_RE.search(env_k):
            safe_env[env_k] = HIDDEN_PASSWORD
        elif isinstance(env_v, str) and HIDDEN_URL_PASSWORD_RE.match(env_v):
            safe_env[env_k] = HIDDEN_URL_PASSWORD_RE.sub(
                HIDDEN_PASSWORD,
                env_v,
            )
    return safe_env


def secret_fields(cred_type: ManagedCredentialType) -> list[str]:
    """List of fields that are sensitive from the credential type.

    :param cred_type: Where the secret field descriptions live
    :return: list of secret field names
    """
    return [
        str(field['id'])
        for field in cred_type.inputs.get('fields', [])
        if field.get('secret', False) is True
    ]


def _build_extra_vars(
    sandbox: ImmutableSandboxedEnvironment,
    namespace: dict[str, TowerNamespaceValueType],
    node: Mapping[str, str | list[str]] | list[str] | str,
) -> ExtraVarsType:
    """Execute template to generate extra vars.

    :param sandbox: jinja2 sandbox environment
    :param namespace: variables available to the jinja2 sandbox
    :param node: extra vars for this iteration
    :return: filled in extra vars node
    """
    if isinstance(node, Mapping):
        return {
            str(
                _build_extra_vars(sandbox, namespace, entry),
            ): _build_extra_vars(
                sandbox,
                namespace,
                v,
            )
            for entry, v in node.items()
        }
    if isinstance(node, list):
        return [_build_extra_vars(sandbox, namespace, entry) for entry in node]
    return sandbox.from_string(node).render(**namespace)


def _build_extra_vars_file(
    extra_vars: ExtraVarsType,
    private_dir: str,
) -> str:
    """Serialize extra vars out to a file.

    :param extra_vars: python dict to serialize
    :param private_dir: base directory to create file in
    :return: path to the file
    """
    handle, path = tempfile.mkstemp(
        dir=os.path.join(private_dir, 'env'),
    )
    f = os.fdopen(handle, 'w')
    f.write(yaml_safe_dump(extra_vars))
    f.close()
    os.chmod(path, stat.S_IRUSR)
    return path


# pylint: disable-next=too-many-arguments,too-many-positional-arguments,too-many-locals,too-many-branches,too-many-statements
def inject_credential(
    cred_type: ManagedCredentialType,
    credential: Credential,
    env: EnvVarsType,
    safe_env: EnvVarsType,
    args: ArgsType,
    private_data_dir: str,
    *,
    container_root: os.PathLike[str] | str | None = None,
) -> None:
    # pylint: disable=unidiomatic-typecheck
    """Inject credential data.

    Inject credential data into the environment variables and arguments
    passed to ansible-playbook

    :param cred_type: an instance of ManagedCredentialType
    :param credential: credential holding the input to be used
    :param env: a dictionary of environment variables used in the
        ansible-playbook call. This method adds additional environment
        variables based on custom environment injectors defined on this
        CredentialType.
    :param safe_env: a dictionary of environment variables stored in the
        database for the job run secret values should be stripped
    :param args: a list of arguments passed to ansible-playbook in the
        style of subprocess.call(). This method appends additional
        arguments based on custom extra_vars injectors defined on this
        CredentialType.
    :param private_data_dir: a temporary directory to store files
        generated by file injectors (like configuration files or key
        files)
    :param container_root: root directory inside the container to mount
        the private data directory to.
    :raises ValueError: if file injectors mix bare ``template`` and
        dotted ``template.<x>`` labels
    :returns: None
    """
    if not cred_type.injectors:
        if cred_type.managed and cred_type.custom_injectors:
            injected_env: EnvVarsType = {}
            cred_type.custom_injectors(
                credential,
                injected_env,
                private_data_dir,
            )
            env.update(injected_env)
            safe_env.update(build_safe_env(injected_env))
        return

    tower_namespace = TowerNamespace()

    # maintain a normal namespace for building the ansible-playbook
    # arguments (env and args)
    namespace: dict[str, TowerNamespaceValueType] = {
        'tower': tower_namespace,
    }

    # maintain a sanitized namespace for building the DB-stored arguments
    # (safe_env)
    safe_namespace: dict[str, TowerNamespaceValueType] = {
        'tower': tower_namespace,
    }

    # build a normal namespace with secret values decrypted (for
    # ansible-playbook) and a safe namespace with secret values hidden (for
    # DB storage)
    for field_name in credential.get_input_keys():
        value = credential.get_input(field_name)

        if type(value) is bool:
            # boolean values can't be secret/encrypted/external
            safe_namespace[field_name] = value
            namespace[field_name] = value
            continue

        if field_name in secret_fields(cred_type):
            safe_namespace[field_name] = HIDDEN_PASSWORD
        elif value:
            safe_namespace[field_name] = value
        if value:
            namespace[field_name] = value

    for field in cred_type.inputs.get('fields', []):
        field_id = str(field['id'])
        field_type_is_bool = field['type'] == 'boolean'
        # default missing boolean fields to False
        if field_type_is_bool and field_id not in credential.get_input_keys():
            namespace[field_id] = False
            safe_namespace[field_id] = False
        # make sure private keys end with a \n
        if field.get('format') == 'ssh_private_key':
            if field_id in namespace and not str(namespace[field_id]).endswith(
                '\n',
            ):
                namespace[field_id] = str(namespace[field_id]) + '\n'

    file_tmpls = cred_type.injectors.get('file', {})
    # If any file templates are provided, render the files and update the
    # special `tower` template namespace so the filename can be
    # referenced in other injectors

    has_bare = any('.' not in label for label in file_tmpls)
    has_dotted = any('.' in label for label in file_tmpls)
    if has_bare and has_dotted:
        msg = (
            "Credential type file injectors cannot mix bare 'template' "
            "and dotted 'template.<x>' labels — the bare value would "
            'overwrite the dotted namespace or vice-versa'
        )
        raise ValueError(msg)

    sandbox_env = ImmutableSandboxedEnvironment()

    # Pass 1: create all files to establish paths, so that
    # tower.filename.* is fully populated before any template
    # might need to cross-reference another file's path.
    file_paths: dict[str, tuple[str, str]] = {}
    file: str | None = None

    for file_label in file_tmpls:
        env_dir = os.path.join(private_data_dir, 'env')
        path = tempfile.mkstemp(dir=env_dir)[1]
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        container_path = get_incontainer_path(path, private_data_dir)
        file_paths[file_label] = (path, container_path)

        if '.' in file_label:
            # SimpleNamespace.__getattribute__ is typed as -> Any in
            # typeshed, so mypy sees this isinstance() as containing Any.
            if not isinstance(tower_namespace.filename, SimpleNamespace):  # type: ignore[misc]
                tower_namespace.filename = SimpleNamespace()
            filename_ns: SimpleNamespace = tower_namespace.filename
            setattr(
                filename_ns,
                file_label.split('.')[1],
                container_path,
            )
        else:
            file = container_path

    if file is not None:
        tower_namespace.filename = file

    # Pass 2: render templates and write files now that all
    # tower.filename.* paths are available for cross-references.
    for tmpl_label, file_tmpl in file_tmpls.items():
        data: str = sandbox_env.from_string(file_tmpl).render(
            **namespace,
        )
        host_path = file_paths[tmpl_label][0]
        pathlib.Path(host_path).write_text(data, encoding='utf-8')

    for env_var, tmpl in cred_type.injectors.get('env', {}).items():
        if env_var in ENV_BLOCKLIST:
            continue
        env[env_var] = sandbox_env.from_string(tmpl).render(**namespace)
        safe_env[env_var] = sandbox_env.from_string(
            tmpl,
        ).render(**safe_namespace)

    if 'INVENTORY_UPDATE_ID' not in env:
        extra_vars = _build_extra_vars(
            sandbox_env,
            namespace,
            cred_type.injectors.get(
                'extra_vars',
                {},
            ),
        )
        if extra_vars:
            path = _build_extra_vars_file(extra_vars, private_data_dir)
            container_path = get_incontainer_path(
                path,
                private_data_dir,
                container_root=container_root,
            )
            args.extend(
                # pylint: disable-next=consider-using-f-string
                ['-e', '@%s' % container_path],
            )
