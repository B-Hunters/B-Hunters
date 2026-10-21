"""The B-Hunters platform: the authenticated API, the agent runtime, the
scanner adapters and the benchmark laboratory.

The platform extends the existing framework rather than replacing it: the
Karton workers, the legacy MongoDB collections and the CLI commands all
keep working unchanged.
"""

from .__version__ import __version__  # noqa: F401
