"""
Single shared Jinja2Templates instance for the entire application.
All routes must import `templates` from here so that globals
(get_flash, etc.) are available in every template.
"""

import os
from pathlib import Path

from fastapi import Request
from fastapi.templating import Jinja2Templates

_templates_dir = str(Path(__file__).resolve().parent / "templates")
templates = Jinja2Templates(directory=_templates_dir)


def _get_flash(request: Request):
    return getattr(request.state, "flash", None)


templates.env.globals["get_flash"] = _get_flash
