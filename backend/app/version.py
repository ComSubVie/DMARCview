"""Version string.

The Docker release workflow sets ``DMARCVIEW_VERSION`` from the git tag. The
literal fallback keeps local source/container builds useful without injecting
a build argument.
"""

import os

VERSION = os.environ.get("DMARCVIEW_VERSION", "").strip() or "1.19.1"
