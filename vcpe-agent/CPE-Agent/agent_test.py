import json
from config_reader import ConfigReader

reader = ConfigReader()
sdwan_root = reader.get_intended_config()

print(json.dumps(sdwan_root, indent=2))

wan_links = sdwan_root.get("interfaces", {}).get("underlay", {}).get("wan-link", [])
lan_links = sdwan_root.get("interfaces", {}).get("lan", {}).get("lan-link", [])

print("WAN links:", len(wan_links))
print("LAN links:", len(lan_links))

for lan in lan_links:
    dhcp = lan.get("dhcp-server", {})
    print(f"LAN {lan.get('name')} DHCP enabled:", dhcp.get("enabled", False))

 try:
        config, changed = reader.get_config_with_change_flag()              # Read the latest config and also check whether it changed

        print("Config changed:", changed)
        print("\nFull intended config:")
        print(json.dumps(config, indent=2))

    except Exception as e:
        print("Error reading config:", e)
