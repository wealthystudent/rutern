"""Typed errors. Messages never carry credentials or raw response bodies."""


class RuternError(Exception):
    """Base for every error rutern raises on purpose."""


class ConfigError(RuternError):
    """Settings (env, saved state, credentials) are invalid or missing."""


class Unreachable(RuternError):
    """The router or the cloud portal did not answer."""


class PermissionDenied(RuternError):
    """The local sysbus refused the call (error 13). Use the cloud path."""


class AuthRequired(RuternError):
    """The cloud session is missing or expired (HTTP 401 / message 10000)."""


class LoginFailed(RuternError):
    """The single cloud login attempt was rejected."""


class LoginBlocked(RuternError):
    """A recent login failed, so further attempts are refused to avoid a lockout."""


class ApiError(RuternError):
    """The router answered with an unexpected status or shape."""


class NotAllowed(RuternError):
    """A guardrail refused the action."""
