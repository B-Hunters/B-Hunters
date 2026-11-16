"""The version of the platform.

It is the version of the package: there is one number, and it is the
one that is published.  A second copy of it here would drift from the
release, and the health endpoint would answer with a version that is
not the one that runs.
"""

from b_hunters.__version__ import __version__

__all__ = ["__version__"]
