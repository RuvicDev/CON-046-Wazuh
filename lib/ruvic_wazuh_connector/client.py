"""Cliente para consultar alertas y agentes en Wazuh.

Capacidades:
- list_alerts():           listar alertas desde el Indexer, con filtro opcional.
- get_agent():              consultar el detalle de un agente en el Manager.
- get_agents_status_summary(): obtener el conteo de agentes por estado.

Wazuh separa sus componentes: el **Manager** (gestión de agentes, API con
JWT en el puerto 55000) y el **Indexer** (basado en OpenSearch, donde
viven las alertas, típicamente puerto 9200) — este cliente habla con
ambos de forma transparente.

Autenticación: Basic Auth contra el Manager para obtener un JWT (válido
15 minutos por defecto, renovado automáticamente), y Basic Auth directo
contra el Indexer para las consultas de alertas. Las credenciales
SIEMPRE provienen de variables de entorno RUVIC_WAZUH_* (ver
config.WazuhConfig.from_env). Prohibido hardcodearlas.
"""

from __future__ import annotations

import time
from typing import Any

import requests
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import RequestException, Timeout

from .config import WazuhConfig
from .exceptions import WazuhAuthError, WazuhDataError, WazuhNetworkError
from .logging_utils import get_logger


class WazuhClient:
    """Cliente de Wazuh (Manager + Indexer).

    Args:
        config: configuración de conexión. Si se omite, se lee de las
            variables de entorno RUVIC_WAZUH_* (comportamiento estándar
            en el runtime de la plataforma).

    Ejemplo:
        >>> client = WazuhClient()  # lee RUVIC_WAZUH_* del entorno
        >>> client.get_agents_status_summary()
        {'active': 12, 'disconnected': 1, 'never_connected': 0, 'pending': 0}
    """

    def __init__(self, config: WazuhConfig | None = None) -> None:
        self.config = config or WazuhConfig.from_env()
        self._logger = get_logger()
        self._manager_token: str | None = None
        self._manager_token_expires_at: float = 0.0

    # ------------------------------------------------------------------ #
    # Autenticación del Manager (JWT, renovado automáticamente)
    # ------------------------------------------------------------------ #

    def _get_manager_token(self) -> str:
        if self._manager_token and time.time() < self._manager_token_expires_at - 30:
            return self._manager_token

        url = f"{self._manager_base_url()}/security/user/authenticate"
        try:
            resp = requests.post(
                url,
                auth=(self.config.manager_username, self.config.manager_password),
                params={"raw": "true"},
                verify=self.config.verify_ssl,
                timeout=self.config.timeout,
            )
        except Timeout as exc:
            raise WazuhNetworkError("Tiempo de espera agotado autenticando con el Manager de Wazuh.") from exc
        except RequestsConnectionError as exc:
            raise WazuhNetworkError(f"No se pudo conectar al Manager ({url}): {exc}") from exc
        except RequestException as exc:
            raise WazuhNetworkError(f"Error de red autenticando con el Manager: {exc}") from exc

        if resp.status_code != 200:
            raise WazuhAuthError(
                f"El Manager rechazó la autenticación (HTTP {resp.status_code}): {resp.text[:300]}. "
                "Revisa manager_username y manager_password."
            )

        self._manager_token = resp.text.strip()
        self._manager_token_expires_at = time.time() + self.config.token_lifetime
        return self._manager_token

    def _manager_base_url(self) -> str:
        return f"https://{self.config.manager_host}:{self.config.manager_port}"

    def _indexer_base_url(self) -> str:
        return f"https://{self.config.indexer_host}:{self.config.indexer_port}"

    # ------------------------------------------------------------------ #
    # Peticiones HTTP
    # ------------------------------------------------------------------ #

    def _manager_request(self, method: str, path: str, **extra: Any) -> requests.Response:
        token = self._get_manager_token()
        url = f"{self._manager_base_url()}{path}"
        headers = extra.pop("headers", {})
        headers["Authorization"] = f"Bearer {token}"
        return self._do_request(method, url, headers=headers, **extra)

    def _indexer_request(self, method: str, path: str, **extra: Any) -> requests.Response:
        url = f"{self._indexer_base_url()}{path}"
        return self._do_request(
            method, url,
            auth=(self.config.indexer_username, self.config.indexer_password),
            **extra,
        )

    def _do_request(self, method: str, url: str, **extra: Any) -> requests.Response:
        try:
            return requests.request(
                method, url, verify=self.config.verify_ssl, timeout=self.config.timeout, **extra
            )
        except Timeout as exc:
            raise WazuhNetworkError(f"Tiempo de espera agotado llamando a {url}.") from exc
        except RequestsConnectionError as exc:
            raise WazuhNetworkError(f"No se pudo conectar a {url}: {exc}") from exc
        except RequestException as exc:
            raise WazuhNetworkError(f"Error de red: {exc}") from exc

    def _raise_for_error(self, resp: requests.Response, context: str) -> None:
        try:
            payload = resp.json()
            message = payload.get("message") or payload.get("error", {}).get("reason") or resp.text[:300]
        except (ValueError, AttributeError):
            message = resp.text[:300] or "Error desconocido"

        if resp.status_code in (401, 403):
            raise WazuhAuthError(f"Permisos insuficientes en {context} (HTTP {resp.status_code}): {message}")
        if resp.status_code == 404:
            raise WazuhDataError(f"No encontrado en {context}: {message}")
        raise WazuhDataError(f"Error de Wazuh en {context} (HTTP {resp.status_code}): {message}")

    # ------------------------------------------------------------------ #
    # Ping / prueba de conexión
    # ------------------------------------------------------------------ #

    def ping(self) -> bool:
        """Verifica ambas conexiones: obtiene un token del Manager y
        consulta el estado de agentes (barato)."""
        self.get_agents_status_summary()
        self._logger.info("Ping exitoso a Wazuh (Manager: %s)", self.config.manager_host)
        return True

    # ------------------------------------------------------------------ #
    # Capacidad 1: listar alertas (Indexer)
    # ------------------------------------------------------------------ #

    def list_alerts(self, query_text: str | None = None, max_results: int = 50) -> list[dict[str, Any]]:
        """Lista alertas desde el Indexer, con un filtro de texto opcional.

        Args:
            query_text: texto de búsqueda libre (sintaxis query_string de
                OpenSearch, ej. "rule.level:>=10"). Si se omite, trae las
                alertas más recientes sin filtrar.
            max_results: máximo de resultados (default 50).

        Returns:
            Lista de dicts con "id", "timestamp", "rule_description",
            "rule_level", "agent_name".

        Ejemplo:
            >>> client.list_alerts(query_text="rule.level:>=10", max_results=10)
            [{'id': '...', 'rule_description': 'Multiple failed logins', ...}, ...]
        """
        body: dict[str, Any] = {
            "size": max_results,
            "sort": [{"timestamp": {"order": "desc"}}],
        }
        body["query"] = {"query_string": {"query": query_text}} if query_text else {"match_all": {}}

        resp = self._indexer_request(
            "POST", "/wazuh-alerts-*/_search", json=body, headers={"Content-Type": "application/json"}
        )
        if resp.status_code != 200:
            self._raise_for_error(resp, "list_alerts")

        hits = resp.json().get("hits", {}).get("hits", [])
        alerts = [self._hit_to_dict(h) for h in hits]
        self._logger.info("list_alerts: %d alerta(s)", len(alerts))
        return alerts

    @staticmethod
    def _hit_to_dict(hit: dict[str, Any]) -> dict[str, Any]:
        source = hit.get("_source", {})
        rule = source.get("rule", {})
        agent = source.get("agent", {})
        return {
            "id": hit.get("_id"),
            "timestamp": source.get("timestamp"),
            "rule_description": rule.get("description"),
            "rule_level": rule.get("level"),
            "agent_name": agent.get("name"),
        }

    # ------------------------------------------------------------------ #
    # Capacidad 2: consultar un agente (Manager)
    # ------------------------------------------------------------------ #

    def get_agent(self, agent_id: str) -> dict[str, Any]:
        """Consulta el detalle de un agente.

        Args:
            agent_id: Id del agente (ej. "001").

        Returns:
            Dict con "id", "name", "ip", "status", "os", "version".

        Ejemplo:
            >>> client.get_agent("001")
            {'id': '001', 'name': 'WKS-001', 'status': 'active', ...}
        """
        if not isinstance(agent_id, str) or not agent_id.strip():
            raise WazuhDataError(f"agent_id debe ser un texto no vacío, recibido: {agent_id!r}.")

        resp = self._manager_request("GET", "/agents", params={"agents_list": agent_id.strip()})
        if resp.status_code != 200:
            self._raise_for_error(resp, f"get_agent {agent_id}")

        items = resp.json().get("data", {}).get("affected_items", [])
        if not items:
            raise WazuhDataError(f"Agente no encontrado: {agent_id!r}")

        item = items[0]
        return {
            "id": item.get("id"),
            "name": item.get("name"),
            "ip": item.get("ip"),
            "status": item.get("status"),
            "os": (item.get("os") or {}).get("name"),
            "version": item.get("version"),
        }

    # ------------------------------------------------------------------ #
    # Capacidad 3: obtener el estado de todos los agentes (Manager)
    # ------------------------------------------------------------------ #

    def get_agents_status_summary(self) -> dict[str, int]:
        """Obtiene el conteo de agentes por estado.

        Returns:
            Dict con conteos por estado, ej. "active", "disconnected",
            "never_connected", "pending".

        Ejemplo:
            >>> client.get_agents_status_summary()
            {'active': 12, 'disconnected': 1, 'never_connected': 0, 'pending': 0}
        """
        resp = self._manager_request("GET", "/agents/summary/status")
        if resp.status_code != 200:
            self._raise_for_error(resp, "get_agents_status_summary")

        data = resp.json().get("data", {})
        connection_summary = data.get("connection", data)
        self._logger.info("get_agents_status_summary: %s", connection_summary)
        return connection_summary
