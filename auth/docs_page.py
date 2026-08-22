"""Self-describing documentation served at ``/``.

The audience is a coding agent that has been handed nothing but the base URL,
so the page has to answer "how do I use this?" without any other source. Every
response shape and status code below was captured from the running service —
keep it that way: if a route's output changes, update the text in the same
commit, otherwise the page becomes a confident liar.

The text itself lives in :mod:`auth.static_docs` as Markdown/HTML data files;
this module is the loader and the routing.
"""

from importlib.metadata import PackageNotFoundError, version

from flask import Response, request

try:
    _VERSION = version("auth")
except PackageNotFoundError:  # source checkout without an install
    _VERSION = "0.0.0.dev0"


def _blob(name: str) -> str:
    """Read one documentation blob from the :mod:`auth.static_docs` package.

    ``importlib.resources`` rather than a path relative to ``__file__`` so the
    text is found the same way whether auth is installed as a wheel, run from a
    source checkout, or imported out of a zip.
    """
    from importlib.resources import files

    return (files("auth.static_docs") / name).read_text(encoding="utf-8")


# Read once at import: these are static and served on every landing hit.
# `{version}` and the doubled braces in the reference are resolved by
# .format() below, exactly as when the text was a module-level literal.
_DOCS = _blob("api_reference.md")
_LANDING = _blob("landing.md")
_CLAUDE_GUIDE = _blob("claude_guide.md")
_HTML = _blob("page.html")


def render_markdown() -> str:
    """The full API reference as Markdown (served at /docs and /llms.txt)."""
    return _DOCS.format(version=_VERSION)


def _coming_soon(label: str) -> str:
    """Placeholder for a per-agent guide route that isn't written yet."""
    return (
        "# " + label + " guide — coming soon\n\n"
        "An " + label + "-specific integration guide for auth is planned but "
        "not written yet. In the meantime:\n\n"
        "- `/docs` — the full API reference (every endpoint + response shape)\n"
        "- `/llms.txt` — the same reference as Markdown, for ingestion\n"
        "- `/claude` — the Claude Code guide; the integration steps are identical,"
        " only the wrapper differs\n\n"
        "auth is RBAC over HTTP: `user → role → permission`, one UUID4 = one "
        "private namespace. `pip install auth` for the Python client, or call the "
        "HTTP API in any language.\n"
    )


def render_landing() -> str:
    """The lean landing page as Markdown (served at /)."""
    return _LANDING.replace("__VERSION__", _VERSION)


def _wants_html() -> bool:
    """True for browsers, false for curl/agents.

    Browsers send an Accept list that prefers text/html; curl sends `*/*` and
    HTTP clients usually ask for JSON. Serving Markdown by default keeps the
    page cheap to parse for the agents it is written for.
    """
    accept = request.accept_mimetypes
    return accept["text/html"] > accept["text/plain"] and accept["text/html"] > 0


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _serve_doc(markdown_text: str) -> Response:
    """Render Markdown as HTML for browsers, plain Markdown for everything else.

    Flask appends `; charset=utf-8` to text/* mimetypes itself — spelling it out
    would emit the parameter twice.
    """
    if _wants_html():
        return Response(_HTML.format(body=_escape(markdown_text)), mimetype="text/html")
    return Response(markdown_text, mimetype="text/markdown")


def register_docs_routes(app):
    """Register the documentation endpoints.

    `/` is a lean landing that routes to the full reference (`/docs`,
    `/llms.txt`) or a per-agent guide (`/claude`, and the placeholder
    `/opencode` / `/codex`). All are public and unmetered.
    """

    @app.route("/", methods=["GET"])
    def index():
        """Lean landing: what auth is, a quickstart, and links to the guides."""
        return _serve_doc(render_landing())

    @app.route("/docs", methods=["GET"])
    def docs():
        """The full API reference."""
        return _serve_doc(render_markdown())

    @app.route("/llms.txt", methods=["GET"])
    def llms_txt():
        """https://llmstxt.org convention — the full reference, always Markdown."""
        return Response(render_markdown(), mimetype="text/markdown")

    @app.route("/claude", methods=["GET"])
    def claude_guide():
        """Claude Code integration guide."""
        return _serve_doc(_CLAUDE_GUIDE)

    @app.route("/opencode", methods=["GET"])
    def opencode_guide():
        """Per-agent guide — placeholder until written."""
        return _serve_doc(_coming_soon("OpenCode"))

    @app.route("/codex", methods=["GET"])
    def codex_guide():
        """Per-agent guide — placeholder until written."""
        return _serve_doc(_coming_soon("Codex"))
