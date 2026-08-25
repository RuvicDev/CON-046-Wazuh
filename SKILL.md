---
name: wazuh
description: "Usa la librería ruvic_wazuh_connector para consultar alertas y agentes en Wazuh - listar alertas con filtro opcional (list_alerts), consultar el detalle de un agente (get_agent), y obtener el conteo de agentes por estado (get_agents_status_summary). Úsala cuando el usuario pida revisar alertas de seguridad, el estado de un endpoint monitoreado, o un resumen de agentes conectados/desconectados. Conector de solo consulta, no modifica agentes ni alertas."
triggers:
- wazuh
- alertas wazuh
- agente wazuh
- xdr
---

# Conector Wazuh (ruvic_wazuh_connector)

Librería Python para consultar alertas y agentes en Wazuh, autenticada con usuario/contraseña contra el Manager y el Indexer. Está **preinstalada en el runtime** cuando el conector está configurado (si no, instálala con `pip install git+https://github.com/tu-org/conector-wazuh.git#subdirectory=lib`).

## Regla crítica de credenciales

El código generado **NUNCA hardcodea credenciales**. Siempre se leen de variables de entorno, disponibles cuando el conector `wazuh` está configurado:

| Variable | Contenido |
|----------|-----------|
| `RUVIC_WAZUH_MANAGER_HOST` / `..._MANAGER_USERNAME` / `..._MANAGER_PASSWORD` | Credenciales del Manager (gestión de agentes) |
| `RUVIC_WAZUH_INDEXER_HOST` / `..._INDEXER_USERNAME` / `..._INDEXER_PASSWORD` | Credenciales del Indexer (alertas) |
| `RUVIC_WAZUH_MANAGER_PORT` / `..._INDEXER_PORT` | (opcional) default `55000`/`9200` |
| `RUVIC_WAZUH_VERIFY_SSL` | (opcional) `true`/`false`, default `true` |
| `RUVIC_WAZUH_REQUEST_TIMEOUT` | (opcional) segundos, default `30` |

Si estas variables NO existen, el conector no está configurado: no generes código que lo use; indica al usuario que lo configure en **Settings → Conectores**.

El código generado **NUNCA** usa nombres de variable con segmento de alias (`_DEFAULT_`, `_TEST_`, `_PRODUCCION_`, etc.) — siempre `{ENV_PREFIX}{CAMPO}` tal cual, sin importar cuántas instancias de este conector haya configuradas. Esto aplica salvo que dichos nombres aparezcan explícitamente en una sección autogenerada al final de este skill.

## Conexión (siempre igual)

```python
from ruvic_wazuh_connector import WazuhClient

client = WazuhClient()  # lee RUVIC_WAZUH_* del entorno automáticamente
```

El cliente gestiona automáticamente el token JWT del Manager (renovándolo cuando expira) y la autenticación del Indexer — no necesitas manejarlo tú.

## Capacidad 1 — Listar alertas

```python
alertas = client.list_alerts(query_text="rule.level:>=10", max_results=20)
for a in alertas:
    print(f"[{a['rule_level']}] {a['rule_description']} - {a['agent_name']}")
```

Sin `query_text`, trae las alertas más recientes sin filtrar.

## Capacidad 2 — Consultar un agente

```python
agente = client.get_agent("001")
print(f"{agente['name']}: {agente['status']}")
```

## Capacidad 3 — Estado general de los agentes

```python
resumen = client.get_agents_status_summary()
print(resumen)  # {'active': 12, 'disconnected': 1, ...}
```

## Manejo de errores

```python
from ruvic_wazuh_connector import WazuhAuthError, WazuhNetworkError, WazuhDataError

try:
    client.get_agents_status_summary()
except WazuhAuthError:
    print("Credenciales inválidas — revisa la configuración del conector")
except WazuhNetworkError:
    print("No se pudo conectar al Manager/Indexer de Wazuh — revisa la red/VPN")
except WazuhDataError as e:
    print(f"Error de datos: {e}")  # ej. agente no encontrado
```

## Buenas prácticas al generar código

1. Lee credenciales SOLO de las variables `RUVIC_WAZUH_*` (el constructor de `WazuhClient` ya lo hace).
2. Nunca imprimas `RUVIC_WAZUH_MANAGER_PASSWORD` ni `RUVIC_WAZUH_INDEXER_PASSWORD` en logs ni en la salida.
3. No intentes modificar agentes ni alertas: este conector es de solo consulta.
4. `list_alerts` sin filtro trae las alertas más recientes sin acotar — usa `query_text` cuando el usuario busque algo específico.
