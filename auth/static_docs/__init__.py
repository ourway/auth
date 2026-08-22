"""Documentation blobs served by :mod:`auth.docs_page`.

These are data files, not source: the API reference, the landing page, the
Claude Code guide and the HTML wrapper. They live here so ``docs_page`` stays a
readable module instead of a 700-line string literal, and so the text can be
diffed and reviewed as Markdown. Shipped as package data — see
``[tool.setuptools.package-data]`` in pyproject.toml.
"""
