# Naming the Ducks

Canonical names for this project, and how to refer to it in
prose. Other files in `.agents-ctx/` (and any generated content)
should say "the project" rather than hardcoding one of these --
reach for a specific name only when the distinction actually
matters (e.g. citing a package, an import, or a repository URL).

## Distribution / PyPI name: `awx_plugins.interfaces`

The installable, published name -- recorded in
`pyproject.toml`'s `[project].name` per PEP 621. This is also
the preferred way to refer to the project by name in prose.
Packaging tools normalize it to `awx-plugins-interfaces` (e.g. in
sdist and wheel file names) -- that's the same distribution, not
a different one.

## Python import name: `awx_plugins.interfaces`

The same as the distribution name. `awx_plugins` is a PEP 420
implicit namespace package shared with other distributions, such
as `awx-plugins-core`, which provides `awx_plugins.credentials.*`.
Neither `src/awx_plugins/` nor `src/awx_plugins/interfaces/` has
an `__init__.py` -- don't add one.

## GitHub repository slug: `ansible/awx_plugins.interfaces`

Use it verbatim when it's actually the repository being
referenced (URLs, `gh` invocations, PR/issue citations) -- not as
a stand-in for the project's name in prose.

## Don't confuse it with `ansible/awx-plugins`

`ansible/awx-plugins` is a separate repository, publishing
`awx-plugins-core` -- the plugins themselves. This project only
holds the interfaces they implement and that AWX consumes. Say
which one is meant.
