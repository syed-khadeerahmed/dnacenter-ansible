
application_details = {'application_name': 'app35', 'type': 'server_ip', 'server_name': 'www.example1.com', 'network_identity_setting': {'protocol': 'TCP', 'port': 2001}, 'dscp': 5, 'traffic_class': 'BROADCAST_VIDEO', 'category_id': 'f502f995-b90f-4c77-ba8e-7acc970dec34', 'application_set_name': 'sampleapplsetTTT'} 

application_set_id = 1111111

# Prepare common application data, ignoring optional fields if not provided
network_application = {
    "applicationType": "CUSTOM",
    "trafficClass": application_details.get("traffic_class"),
    "categoryId": application_details.get("category_id"),
    "type": "_server-ip" if application_details.get("type") == "server_ip" else
            "_url" if application_details.get("type") == "url" else "_servername"
}

# Add optional fields if they exist in the application_details
optional_fields = [
    ("ignore_conflict", "ignoreConflict"),
    ("rank", "rank"),
    ("engine_id", "engineId"),
    ("helpstring", "helpString"),
    ("description", "longDescription")
]

for field, key in optional_fields:
    value = application_details.get(field)
    if value is not None:  # Only add to payload if the value exists
        network_application[key] = value if key not in ("rank", "engineId") else int(value)

# Add specific fields for 'server_name', 'url', or 'server_ip'
app_type = application_details.get("type")

if app_type == "server_name":
    if application_details.get("server_name") is None:
        raise ValueError("server_name is required for the type - server_name")
    network_application["serverName"] = application_details.get("server_name")
elif app_type == "url":
    if application_details.get("app_protocol") is None or application_details.get("url") is None:
        raise ValueError("app_protocol and url are required for the type - url")
    network_application["appProtocol"] = application_details.get("app_protocol")
    network_application["url"] = application_details.get("url")

# Handle the conditional inclusion of `dscp` or `network_identity_setting` (or both)
dscp = application_details.get("dscp")
network_identity_setting = application_details.get("network_identity_setting", {})

network_identity_list = None  # Default to None

if app_type == "server_ip":
    if not dscp and not network_identity_setting:
        raise ValueError("Either 'dscp' or 'network_identity_setting' must be provided.")

    # Add dscp if present
    if dscp:
        network_application["dscp"] = dscp

    # Add network_identity_setting if present
    if network_identity_setting:
        protocol = network_identity_setting.get("protocol")
        ports = network_identity_setting.get("port")

        # Raise an error if mandatory fields are missing
        if not protocol or not ports:
            raise ValueError("Both 'protocol' and 'ports' are required for server_ip type.")

        # Prepare networkIdentity dictionary with mandatory and optional fields
        network_identity = {
            "protocol": protocol,
            "ports": str(ports)  # Ensure port is a string
        }

        # Optional fields for networkIdentity
        optional_network_identity_fields = [
            ("ip_subnet", "ipv4Subnet"),
            ("lower_port", "lowerPort"),
            ("upper_port", "upperPort")
        ]

        for field, key in optional_network_identity_fields:
            value = network_identity_setting.get(field)
            if value is not None:
                network_identity[key] = value

        # Include networkIdentity in the payload
        network_identity_list = [network_identity]

# Prepare the rest of the payload
param = {
    "name": application_details.get("application_name"),
    "parentScalableGroup": {
        "idRef": application_set_id
    },
    "scalableGroupType": "APPLICATION",
    "type": "scalablegroup",
    "networkApplications": [network_application],
}

# Add networkIdentity if it exists
if network_identity_list:
    param["networkIdentity"] = network_identity_list

# Convert to JSON for output
import json
print(json.dumps([param], indent=4))