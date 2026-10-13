"""Every shipped script must resolve to a real capability id.

Why this test exists: `capabilities.py` is the answer to "what can this host
actually do", and a script it cannot resolve answers as *unknown* -- which an
agent reads as "no requirements" or skips, exactly when the script is the one
it needed. Three scripts sat in that state at once (`ete_module.py`,
`device_shell.py`, `rasc_build.py`), and the reason was structural: nothing
checked the registry against the scripts directory, so a script could be added
to `references/routing.md` and `SKILL.md` and still be invisible to the one
command an agent runs to decide whether to use it.

Two properties are asserted, both from the filesystem rather than from the
registry's own self-description:

  * every script resolves -- through its own `capability:` declaration or
    through `SCRIPT_CAPABILITIES` -- to at least one id that exists in
    `CAPABILITIES`;
  * a capability's forward `scripts` list and the reverse
    `SCRIPT_CAPABILITIES` map agree, so a name listed under a capability is
    actually reachable from that name.

`elf_runtime.py` is the regression specimen for the declaration channel: it
declares `static_native` on the first line of its docstring, which is the
documented position, and which a previous window skipped.
"""
from __future__ import annotations

import pytest

from conftest import SCRIPTS_DIR, load_script

cap = load_script("capabilities.py")
pytestmark = pytest.mark.unit

SELF_REPORTING: frozenset = getattr(cap, "SELF_SCRIPTS", frozenset())


def shipped_scripts():
    """Scripts the kit ships, excluding the two that report on the environment."""
    found = sorted(
        p.name for pattern in ("*.py", "*.js") for p in SCRIPTS_DIR.glob(pattern)
    )
    return [name for name in found if name not in SELF_REPORTING]


def test_scripts_directory_is_not_empty():
    # Guards the two tests below against passing on an accidental empty list.
    assert len(shipped_scripts()) > 50, shipped_scripts()


@pytest.mark.parametrize("name", shipped_scripts())
def test_script_resolves_to_a_known_capability(name):
    ids, source = cap.capabilities_for_script(name, str(SCRIPTS_DIR / name))
    assert ids, "%s resolves to %r (source=%s); an unresolved script is reported " \
                "as unknown, so an agent cannot tell what it needs" % (name, ids, source)
    unknown = [i for i in ids if i not in cap.CAPABILITIES]
    assert not unknown, "%s names %s, which is not in CAPABILITIES" % (name, unknown)


@pytest.mark.parametrize(
    "capability_id,script",
    [
        (cid, script)
        for cid, spec in cap.CAPABILITIES.items()
        for script in spec.get("scripts", [])
    ],
)
def test_forward_script_list_is_reachable_from_its_name(capability_id, script):
    path = SCRIPTS_DIR / script
    assert path.exists(), "%s lists %s, which is not shipped" % (capability_id, script)
    declared, _ = cap.declared_capability(str(path))
    effective = declared or cap.SCRIPT_CAPABILITIES.get(script)
    assert capability_id in (effective or []), \
        "%s lists %s, but resolving %s gives %r" % (
            capability_id, script, script, effective)


def test_declaration_is_read_from_the_documented_position(tmp_path):
    """`capability:` on the first docstring line is a declaration, not prose."""
    script = tmp_path / "declared_script.py"
    script.write_text(
        '#!/usr/bin/env python3\n"""capability: static_native\nSummary line.\n"""\n',
        encoding="utf-8",
    )
    ids, source = cap.declared_capability(str(script))
    assert ids == ["static_native"], "first-line declaration was skipped: %r" % (ids,)
    assert source == "declared"


def test_declaration_prose_deeper_in_the_docstring_is_ignored(tmp_path):
    """A `capability:` example in the body is documentation, not a declaration.

    Reading it as one is what would make `capabilities.py` claim a capability
    literally named `<capability_id>` -- the failure its own docstring warns
    about, and the reason only the first line is consulted.
    """
    script = tmp_path / "prose_script.py"
    script.write_text(
        '#!/usr/bin/env python3\n"""Summary.\n\n'
        '    capability: <capability_id>\n"""\n',
        encoding="utf-8",
    )
    ids, source = cap.declared_capability(str(script))
    assert ids is None, "a prose example was read as a declaration: %r" % (ids,)


def test_the_ete_and_build_scripts_are_not_invisible():
    """The three regressions this file was written for, pinned by name.

    `rasc_build.py` was already listed by `dex_index_rust` and still resolved
    to nothing, which is how invisible this could get: the forward list and the
    reverse map had no reason to agree.
    """
    for name in ("ete_module.py", "device_shell.py", "rasc_build.py"):
        ids, source = cap.capabilities_for_script(name, str(SCRIPTS_DIR / name))
        assert ids and all(i in cap.CAPABILITIES for i in ids), \
            "%s resolves to %r (source=%s)" % (name, ids, source)
