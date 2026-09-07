"""Software version of the installed distribution, distinct from protocol profiles."""

from importlib.metadata import PackageNotFoundError, version

try:
    VERSION = version("clearproof")
except PackageNotFoundError:
    VERSION = "unknown"
