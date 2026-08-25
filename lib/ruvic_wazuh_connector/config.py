"""Configuración del conector leída desde variables de entorno.

Convención de la plataforma: cada campo del formulario de configuración
llega como variable de entorno {ENV_PREFIX}{CAMPO} en mayúsculas.
Para este conector el prefijo es RUVIC_WAZUH_.

Wazuh separa sus componentes: el Manager (gestión de agentes, API JWT en
el puerto 55000) y el Indexer (basado en OpenSearch, donde viven las
alertas, típicamente puerto 9200) — con credenciales y hosts propios
cada uno.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

ENV_PREFIX = "RUVIC_WAZUH_"

_DEFAULT_MANAGER_PORT = 55000
_DEFAULT_INDEXER_PORT = 9200
_DEFAULT_TOKEN_LIFETIME = 850  # segundos, con margen bajo el default de Wazuh (900s)


@dataclass(frozen=True)
class WazuhConfig:
    """Parámetros de conexión al Manager y al Indexer de Wazuh."""

    manager_host: str
    manager_username: str
    manager_password: str
    indexer_host: str
    indexer_username: str
    indexer_password: str
    manager_port: int = _DEFAULT_MANAGER_PORT
    indexer_port: int = _DEFAULT_INDEXER_PORT
    verify_ssl: bool = True
    token_lifetime: int = _DEFAULT_TOKEN_LIFETIME
    timeout: int = 30

    @classmethod
    def from_env(cls) -> "WazuhConfig":
        """Construye la configuración desde las variables RUVIC_WAZUH_*.

        Raises:
            ValueError: si falta algún campo obligatorio.
        """
        fields = {
            "manager_host": "MANAGER_HOST",
            "manager_username": "MANAGER_USERNAME",
            "manager_password": "MANAGER_PASSWORD",
            "indexer_host": "INDEXER_HOST",
            "indexer_username": "INDEXER_USERNAME",
            "indexer_password": "INDEXER_PASSWORD",
        }
        values = {k: os.environ.get(f"{ENV_PREFIX}{v}", "").strip() for k, v in fields.items()}
        missing = [f"{ENV_PREFIX}{fields[k]}" for k, v in values.items() if not v]
        if missing:
            raise ValueError(
                "Faltan variables de entorno del conector wazuh: "
                + ", ".join(missing)
                + ". Configura el conector en Settings → Conectores."
            )

        verify_ssl_raw = os.environ.get(f"{ENV_PREFIX}VERIFY_SSL", "true").strip().lower()

        return cls(
            **values,
            manager_port=int(os.environ.get(f"{ENV_PREFIX}MANAGER_PORT", str(_DEFAULT_MANAGER_PORT))),
            indexer_port=int(os.environ.get(f"{ENV_PREFIX}INDEXER_PORT", str(_DEFAULT_INDEXER_PORT))),
            verify_ssl=verify_ssl_raw not in ("false", "0", "no"),
            token_lifetime=int(
                os.environ.get(f"{ENV_PREFIX}TOKEN_LIFETIME", str(_DEFAULT_TOKEN_LIFETIME))
            ),
            timeout=int(os.environ.get(f"{ENV_PREFIX}REQUEST_TIMEOUT", "30")),
        )
