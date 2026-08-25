"""Excepciones propias del conector Wazuh.

Separan los tipos de fallo que el usuario debe distinguir: configuración
inválida, autenticación (JWT del manager, o credenciales del indexer),
red, y datos (agente inexistente, consulta inválida).
"""


class WazuhConnectorError(Exception):
    """Error base del conector."""


class WazuhConfigError(WazuhConnectorError):
    """Configuración inválida: falta un campo requerido."""


class WazuhAuthError(WazuhConnectorError):
    """Credenciales inválidas para el manager (JWT) o el indexer (OpenSearch)."""


class WazuhNetworkError(WazuhConnectorError):
    """No se pudo alcanzar el manager o el indexer de Wazuh (DNS, timeout, red, TLS)."""


class WazuhDataError(WazuhConnectorError):
    """La operación es válida pero el agente no existe, o Wazuh rechazó
    la operación por otra razón."""
