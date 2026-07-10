from soc_tool.api.client import WazuhClient

client = WazuhClient()

alerts = client.get_alerts(limit=5)

print(f"Alerts received: {len(alerts)}")

for alert in alerts:
    print("-" * 50)
    print(f"Time: {alert.timestamp}")
    print(f"Agent: {alert.agent_name}")
    print(f"Rule: {alert.rule_id}")
    print(f"Level: {alert.rule_level}")
    print(f"User: {alert.username}")
    print(f"Source IP: {alert.source_ip}")