# Extract DSCP settings from required details
want_dscp_settings = {key.upper(): value.upper() if isinstance(value, str) else value
                      for key, value in required_details['dscp_settings'].items()}

# Current DSCP settings from the queuing profile
have_dscp_settings = {
    tc['trafficClass']: tc['dscp']
    for tc in queuing_profile['current_queuing_profile'][0]['clause'][1]['tcDscpSettings']
}

# Output the extracted data
self.log("\nWant DSCP Settings:")
self.log(want_dscp_settings)

self.log("\nHave DSCP Settings:")
self.log(have_dscp_settings)

# Initialize final dictionary for DSCP
final_want_dscp_dict = {}

# Compare and update DSCP settings
for traffic_class, want_value in want_dscp_settings.items():
    # Convert want_value to int for comparison
    want_value = int(want_value)

    if traffic_class in have_dscp_settings:
        have_value = have_dscp_settings[traffic_class]
        # Compare values
        if want_value == have_value:
            final_want_dscp_dict[traffic_class] = have_value
        else:
            final_want_dscp_dict[traffic_class] = want_value
    else:
        # If the traffic class is only in want
        final_want_dscp_dict[traffic_class] = want_value

# Final result
self.log("Final Want DSCP Dict:")
self.log(final_want_dscp_dict)

id_dscp_mapping = {}

# Navigate through the queuing profile to map DSCP instance IDs
current_profiles = queuing_profile.get('current_queuing_profile', [])
for profile in current_profiles:
    for clause in profile.get('clause', []):
        if clause.get('type') == 'DSCP_CUSTOMIZATION':
            for dscp_setting in clause.get('tcDscpSettings', []):
                dscp = dscp_setting.get('dscp')
                traffic_class = dscp_setting.get('trafficClass')
                instance_id = dscp_setting.get('instanceId')
                if dscp and traffic_class and instance_id:
                    id_dscp_mapping[traffic_class] = instance_id

update_required = False

# Checking DSCP settings
for key, value in final_want_dscp_dict.items():
    if key in have_dscp_settings:
        if int(have_dscp_settings[key]) != value:
            update_required = True
    else:
        update_required = True

if not update_required:
    self.log("No updates required for DSCP settings. Both dictionaries match.")
else:
    self.log("Update required for DSCP settings.")

# Construct the payload for DSCP customization
instance_ids = {}
for clause in queuing_profile['current_queuing_profile'][0]['clause']:
    if clause['type'] == 'DSCP_CUSTOMIZATION':
        instance_ids['dscp'] = clause['instanceId']

import json

# Base structure for the payload
param = {
    "id": 1,
    "name": "QueueingProfileNew1001",
    "description": "This is a sample test description",
    "clause": [
        {
            "instanceId": 123456789,
            "type": "BANDWIDTH",
            "isCommonBetweenAllInterfaceSpeeds": False,
            "interfaceSpeedBandwidthClauses": []
        }
    ]
}

# Loop through the speeds and bandwidth settings to create the clauses dynamically
for speed, bandwidth_settings in instance_id_bandwidth_settings.items():
    clause = {
        "instanceId": 11111111111,
        "interfaceSpeed": speed,
        "tcBandwidthSettings": []
    }

    for traffic_class, instance_id in bandwidth_settings.items():
        clause["tcBandwidthSettings"].append({
            "trafficClass": traffic_class,
            "instanceId": instance_id,
            "bandwidthPercentage": final_bandwidth_settings[speed].get(traffic_class, 0)
        })

    # Append the clause to the interfaceSpeedBandwidthClauses
    param["clause"][0]["interfaceSpeedBandwidthClauses"].append(clause)

# Check if DSCP settings are available and add them to the payload
if final_want_dscp_dict:
    dscp_clause = {
        "instanceId": 987654321,
        "type": "DSCP_CUSTOMIZATION",
        "tcDscpSettings": []
    }

    for traffic_class, dscp_value in final_want_dscp_dict.items():
        dscp_clause["tcDscpSettings"].append({
            "trafficClass": traffic_class,
            "dscp": dscp_value
        })

    # Add DSCP clause to the payload
    param["clause"].append(dscp_clause)

# Add the generated param to the payload
payload = [param]

# Print the result as a JSON string
print(json.dumps(payload, indent=2))

self.log(json.dumps(payload, indent=2))
