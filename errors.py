class ValidationError(ValueError):
    """Incomplete or unsupported input."""

class APIError(RuntimeError):
    """Sanitized API error."""
