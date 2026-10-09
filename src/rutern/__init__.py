"""Read and configure a Telenor Zyxel EX5700 router."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("rutern")  # set in pyproject.toml; `uv version --bump` changes it
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "0+unknown"
