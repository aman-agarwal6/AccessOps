class IntegrationError(RuntimeError):
    """Sanitized operational failure; never include remote response bodies."""


class TokenValidationError(IntegrationError):
    pass


class ConnectorError(IntegrationError):
    pass


class PolicyUnavailable(IntegrationError):
    pass
