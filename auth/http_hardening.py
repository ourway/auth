import base64
import hashlib
import re

from flask import request
from werkzeug.exceptions import HTTPException

from auth.docs_page import _HTML
from auth.response_format import APIResponse

API_PREFIX = "/api/"
STYLE_BLOCK = re.compile(r"<style>(.*?)</style>", re.DOTALL)


def _style_hash(rendered_page: str) -> str:
    match = STYLE_BLOCK.search(rendered_page)
    style_text = match.group(1) if match else ""
    digest = hashlib.sha256(style_text.encode("utf-8")).digest()
    return "sha256-" + base64.b64encode(digest).decode("ascii")


CONTENT_SECURITY_POLICY = (
    "default-src 'none'; "
    f"style-src '{_style_hash(_HTML.format(body=''))}'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)


def _api_error(error: HTTPException):
    code = error.code or 500
    response, status = APIResponse.error(error.description or error.name, code)
    for name, value in error.get_headers():
        if name.lower() != "content-type":
            response.headers[name] = value
    if code == 401:
        response.headers["WWW-Authenticate"] = "Bearer"
    return response, status


def _set_headers(response):
    response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    if request.path.startswith(API_PREFIX):
        response.headers["Cache-Control"] = "no-store"
    return response


def register(app):
    @app.errorhandler(HTTPException)
    def _http_error(error: HTTPException):
        if request.path.startswith(API_PREFIX):
            return _api_error(error)
        return error

    app.after_request(_set_headers)
