"""B-Hunters - a Karton based bug bounty and application security platform.

Historically this package was declared as a ``pkg_resources`` namespace
package.  ``pkg_resources`` is deprecated and is removed in modern
setuptools, so the package now declares itself normally.  The
``b_hunters.bhunter`` base class - which every worker in the B-Hunters
module repositories imports - remains importable from this package.
"""

from .__version__ import __version__

__all__ = ["__version__"]
