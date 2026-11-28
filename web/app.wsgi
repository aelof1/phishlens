"""Apache mod_wsgi entry point. The application lives in phishlens/web/app.py."""

import sys
from pathlib import Path

# Make the phishlens package (parent folder) importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from phishlens.web.app import application, read_form  # noqa: E402,F401
