"""Prueba de conexión estándar del conector wazuh.

Firma estándar Ruvic: def test_connection() -> tuple[bool, str]
- Lee la configuración EXCLUSIVAMENTE de las env vars RUVIC_WAZUH_*.
- Nunca lanza excepciones; retorna (ok, mensaje).

Ejecutable también como script para pruebas locales:
    python test_connection.py
"""

from __future__ import annotations


def test_connection() -> tuple[bool, str]:
    """Verifica las credenciales obteniendo el resumen de estado de agentes."""
    try:
        from ruvic_wazuh_connector import (
            WazuhAuthError,
            WazuhClient,
            WazuhDataError,
            WazuhNetworkError,
        )
    except ImportError:
        return (
            False,
            "La librería ruvic-wazuh-connector no está instalada. "
            "Instala con: pip install git+https://github.com/tu-org/"
            "conector-wazuh.git#subdirectory=lib",
        )

    try:
        client = WazuhClient()  # valida config
    except ValueError as exc:
        return False, str(exc)

    try:
        client.ping()
    except WazuhAuthError as exc:
        return False, f"Autenticación fallida: {exc}"
    except WazuhNetworkError as exc:
        return False, f"Error de red: {exc}"
    except WazuhDataError as exc:
        return False, f"Error de datos: {exc}"
    except Exception as exc:  # red de seguridad: jamás propagar
        return False, f"Error inesperado: {exc}"

    return True, f"Conexión exitosa al Manager {client.config.manager_host}"


if __name__ == "__main__":
    ok, message = test_connection()
    print(f"{'OK' if ok else 'FALLO'}: {message}")
    raise SystemExit(0 if ok else 1)
