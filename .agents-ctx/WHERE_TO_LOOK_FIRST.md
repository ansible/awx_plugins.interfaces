# Where to Look First

When picking up a task, get oriented before proposing anything.
Read, in this order:

1. The packaging metadata -- what the project is, what it depends
   on, what it exposes.
2. The source of the module the task is about.
3. The shared test fixtures, then the tests for that module --
   they are the behavioral contract.
4. `tox.ini` and `.pre-commit-config.yaml` -- how things get run
   locally and in CI.
5. The main CI/CD workflow.

Here:

1. `pyproject.toml` (setuptools with `setuptools-scm`, and the
   metadata).
2. `src/awx_plugins/interfaces/<module>.py`. `api.py` is the
   public entry point; the `_temporary_private_*` modules hold
   code shared with AWX until it's refactored into a proper
   public interface.
3. There's no `tests/conftest.py`; go straight to
   `tests/<module>_test.py`.
4. As above, plus `toxfile.py` -- an in-tree tox plugin that
   installs from the lock files and adds the `pip-compile*` envs.
5. `.github/workflows/ci-cd.yml`, which delegates to
   `tox-dev/workflow`'s `reusable-tox.yml`.

Other places worth knowing:

- `dependencies/` -- direct dependencies per tox env under
  `direct/`, and the pinned `lock-files/` generated from them.
  Never edit `lock-files/` by hand -- the `pip-tools` GitHub
  Actions workflow regenerates them (see
  `dependencies/README.md`).
- `_type_stubs/` -- type stubs for the parts of AWX and Django
  the code refers to.
- `docs/` -- Sphinx docs (MyST Markdown); `docs/contributing/`
  includes the root `CONTRIBUTING.md`.
- `nitpick-style.toml` -- the style the `nitpick-check` hook
  checks the tool configs against.
