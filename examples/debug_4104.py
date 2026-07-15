"""
Debug recent PowerShell 4104 alerts from Wazuh.
"""

from soc_tool.api.alerts import AlertService


def main() -> None:
    service = AlertService()

    alerts = service.get_by_event_ids(
        event_ids=["4104"],
        limit=500,
    )

    print(f"4104 alerts retrieved: {len(alerts)}")

    for alert in alerts:
        print()
        print("=" * 60)
        print(f"Timestamp:         {alert.timestamp}")
        print(f"Agent:             {alert.agent_name}")
        print(f"Event ID:          {alert.event_id}")
        print(f"Username:          {alert.username}")
        print(f"Script block text: {alert.script_block_text}")
        print("=" * 60)


if __name__ == "__main__":
    main()

