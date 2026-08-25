"""Validación local del conector wazuh: ejercita las 3 capacidades.

Requiere las env vars RUVIC_WAZUH_* exportadas contra un despliegue real
de Wazuh (Manager + Indexer). Puedes usar la demo pública oficial de
Wazuh, o una instalación propia de prueba.
"""

from ruvic_wazuh_connector import WazuhClient, setup_logging

setup_logging("INFO")
client = WazuhClient()

print("== 1. Estado general de los agentes ==")
resumen = client.get_agents_status_summary()
print(f"  {resumen}")

print("== 2. Listar alertas recientes ==")
alertas = client.list_alerts(max_results=5)
print(f"  {len(alertas)} alerta(s)")
for a in alertas:
    print(f"    {a}")

print("== 3. Consultar el agente 000 (el propio Manager, siempre existe) ==")
agente = client.get_agent("000")
print(f"  {agente}")

print("\nValidación completa.")
