# conector-wazuh

Conector Ruvic para Wazuh: listar alertas, consultar un agente, y obtener el estado de los agentes.

## Capacidades

`list_alerts`, `get_agent`, `get_agents_status_summary`. Conector de solo consulta — no modifica agentes ni alertas.

## Arquitectura: dos componentes de Wazuh

Este conector habla con **dos servicios distintos** de Wazuh, cada uno con sus propias credenciales:
- **Manager** (puerto 55000): gestión de agentes, autenticación JWT vía Basic Auth.
- **Indexer** (puerto 9200, basado en OpenSearch): almacena las alertas, autenticación Basic Auth directa.

## Instalación

Requiere **Python ≥ 3.10**.

```bash
pip install git+https://github.com/tu-org/conector-wazuh.git#subdirectory=lib
```

Para desarrollo local (editable, en un venv limpio):

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ./lib
```

## Variables de entorno

| Variable | Obligatoria | Descripción |
|----------|-------------|-------------|
| `RUVIC_WAZUH_MANAGER_HOST` / `..._MANAGER_USERNAME` / `..._MANAGER_PASSWORD` | Sí | Credenciales del Manager |
| `RUVIC_WAZUH_INDEXER_HOST` / `..._INDEXER_USERNAME` / `..._INDEXER_PASSWORD` | Sí | Credenciales del Indexer |
| `RUVIC_WAZUH_MANAGER_PORT` | No | Default `55000` |
| `RUVIC_WAZUH_INDEXER_PORT` | No | Default `9200` |
| `RUVIC_WAZUH_VERIFY_SSL` | No | `true`/`false`, default `true` |
| `RUVIC_WAZUH_TOKEN_LIFETIME` | No | Segundos, default `850` (bajo el default de Wazuh de 900s) |
| `RUVIC_WAZUH_REQUEST_TIMEOUT` | No | Segundos, default `30` |

## Permisos / prerrequisitos en Wazuh

1. En el Manager, crea un usuario con un rol RBAC de solo lectura sobre agentes (no uses `wazuh`/admin completo si puedes acotarlo).
2. En el Indexer, crea un usuario con permiso de lectura sobre el índice `wazuh-alerts-*`.
3. Anota los hosts y puertos de ambos componentes (pueden estar en el mismo servidor o en servidores distintos, según tu despliegue).

## Cómo correr las pruebas locales

Wazuh es open source — puedes instalarlo tú mismo, o usar la **demo pública oficial** que Wazuh mantiene para pruebas sin instalar nada.

```bash
export RUVIC_WAZUH_MANAGER_HOST=tu-wazuh.miempresa.com
export RUVIC_WAZUH_MANAGER_USERNAME=wazuh-wui
export RUVIC_WAZUH_MANAGER_PASSWORD=xxxxxxxx
export RUVIC_WAZUH_INDEXER_HOST=tu-wazuh.miempresa.com
export RUVIC_WAZUH_INDEXER_USERNAME=admin
export RUVIC_WAZUH_INDEXER_PASSWORD=xxxxxxxx

python test_connection.py
python validate_local.py
```

## Limitaciones conocidas

- No modifica agentes (no puede reiniciarlos, eliminarlos, ni añadir nuevos) ni gestiona reglas/decoders.
- `list_alerts` usa la sintaxis `query_string` de OpenSearch — filtros más complejos (agregaciones, rangos de fecha estructurados) no están expuestos en esta versión.
- El token JWT del Manager expira cada 15 minutos por defecto — el cliente lo renueva automáticamente, pero si cambias la configuración de expiración en tu Wazuh, ajusta `RUVIC_WAZUH_TOKEN_LIFETIME` acorde.

## Notas de integración

- El paquete pip es `ruvic-wazuh-connector`; el import name es `ruvic_wazuh_connector`.
- Única dependencia externa: `requests`.
- Ver `SKILL.md` para los ejemplos de uso que consume el agente.
