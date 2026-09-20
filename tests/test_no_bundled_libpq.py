"""auth must never pull a libpq bundled inside a wheel.

psycopg[binary] ships its own libpq. Any consumer connecting with
sslmode=verify-full then has certificate verification performed by whatever
that wheel happened to bundle -- not by the libpq the operator patches, and not
by anything a security update can reach. A pip resolve can change the verifier
with no diff and no review.

auth declared psycopg[binary] as a plain runtime dependency, so every consumer
inherited that and could not opt out: dropping the extra from their own package
had no effect, because ours reinstalled it. Reported by runflow-3858c4 with
measurements from their production.

Two assertions, because the fix has two ways of silently not working:

  the declaration   a future edit re-adding [binary], or an extra that
                    reintroduces it
  the environment   psycopg prefers c -> binary -> python, so an already
                    installed psycopg-binary keeps being used after the
                    declaration changes. The change then looks applied and
                    does nothing.
"""

import pathlib
import re

import pytest

PYPROJECT = pathlib.Path(__file__).resolve().parent.parent / "pyproject.toml"


def _psycopg_requirements():
    text = PYPROJECT.read_text()
    found = re.findall(r'"(psycopg[^"]*)"', text)
    assert found, (
        "no psycopg requirement found in pyproject.toml at all -- the regex is "
        "not matching, so every assertion below would pass by finding nothing"
    )
    return found


def test_no_requirement_pulls_a_bundled_libpq():
    offenders = [r for r in _psycopg_requirements() if "binary" in r]
    assert not offenders, (
        f"{offenders} bundles its own libpq inside the wheel, which moves "
        "certificate verification out of the operator's control. Use plain "
        "psycopg (ctypes against the system libpq) or the 'c' extra "
        "(compiled against the system libpq); never [binary]."
    )


def test_the_runtime_dependency_is_plain_psycopg():
    runtime = [r for r in _psycopg_requirements() if r.startswith("psycopg>")]
    assert runtime, (
        f"expected a plain 'psycopg>=...' runtime requirement; found "
        f"{_psycopg_requirements()}"
    )


def test_the_installed_implementation_is_not_bundled():
    """The environment, not the declaration -- these fail independently."""
    psycopg = pytest.importorskip("psycopg")
    impl = psycopg.pq.__impl__
    assert impl in ("python", "c"), (
        f"psycopg is using the '{impl}' implementation, which carries a "
        "bundled libpq. Changing pyproject.toml does not uninstall an existing "
        "psycopg-binary and psycopg prefers it, so the declaration can be "
        "correct while the environment is not: pip uninstall psycopg-binary."
    )
