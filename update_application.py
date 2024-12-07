application_details = {'current_application': [{'id': '7abe2690-5ac5-4042-8562-0a39a2818eb9', 'instanceId': 15822142, 'instanceVersion': 0, 'identitySource': {'id': 'da9fe3f8-58f4-4234-92bb-f7c6ec129437', 'type': 'APIC-EM'}, 'indicativeNetworkIdentity': [], 'name': 'sample50', 'namespace': 'scalablegroup:application', 'networkApplications': [{'id': '145acd32-7e6f-4c07-9751-89db3d8985bc', 'applicationSubType': 'NONE', 'applicationType': 'CUSTOM', 'categoryId': '49b5f8f0-bdcd-4c71-a7d3-6c29059f5a19', 'helpString': 'sample', 'longDescription': 'sample', 'name': 'sample50', 'popularity': 0, 'rank': 1, 'selectorId': '3402', 'serverName': 'www.sampleserverapp50.com', 'trafficClass': 'BROADCAST_VIDEO', 'displayName': '131685589'}], 'networkIdentity': [], 'parentScalableGroup': {'id': '38c4981d-94f7-43fc-983a-22785e4857c4', 'idRef': 'bd57c8e7-d96d-4975-b130-35e502657786'}, 'qualifier': 'application', 'scalableGroupExternalHandle': 'sample50', 'scalableGroupType': 'APPLICATION', 'type': 'scalablegroup', 'displayName': '15822142'}], 'application_exists': True, 'current_application_set': [{'id': 'bd57c8e7-d96d-4975-b130-35e502657786', 'identitySource': {'id': '238bdc94-50e6-44dc-97d5-5fee25559da0', 'type': 'NBAR'}, 'name': 'authentication-services'}], 'application_set_exists': True} 
required_application_details = {'application_name': 'sample50', 'description': 'samplee', 'helpstring': 'sample', 'type': 'server_name', 'server_name': 'www.sampleserverapp50.com', 'traffic_class': 'network_control', 'category_id': '49b5f8f0-bdcd-4c71-a7d3-6c29059f5a19', 'ignore_conflict': True, 'rank': '1', 'engineId': '100', 'application_set_name': 'authentication_services'} 

current_application_details = application_details.get("current_application")[0]
application_set_id = application_details.get("current_application_set")[0].get("id")
# print(current_application_details)
# print(application_set_id)

if required_application_details.get("application_name") != current_application_details.get("name"):
    print("application name cant be updated")

# Define the mappings for comparison
fields_to_check = {
    "description": "longDescription",
    "helpstring": "helpString",
    "traffic_class": "trafficClass"
}
update_required_keys = []
# Check and print message if update not required
for required_key, current_key in fields_to_check.items():
    if required_application_details.get(required_key) == current_application_details.get("networkApplications")[0].get(current_key):
        print(f"update not required for {required_key}")
    else:
        print(f"update required for {required_key}")
        update_required_keys.append(required_key)
# Check for application_set_id
if application_set_id == current_application_details.get("parentScalableGroup").get("idRef"):
    print("update not required for application_set")
else:
    print("update required for application set")
    update_required_keys.append("application_set")

if not update_required_keys:
    print ("stop the code saying update not required for application")

#construct payload 

# Updated payload construction with values from required_application_details if update is required
param = [
    {
        "id": current_application_details.get("id"),
        "instanceId": current_application_details.get("instanceId"),
        "displayName": current_application_details.get("displayName"),
        "instanceVersion": current_application_details.get("instanceVersion"),
        "name": current_application_details.get("name"),
        "namespace": current_application_details.get("namespace"),
        "networkApplications": [
            {
                "id": current_application_details.get("networkApplications")[0].get("id"),
                "applicationSubType": current_application_details.get("networkApplications")[0].get("applicationSubType"),
                "applicationType": current_application_details.get("networkApplications")[0].get("applicationType"),
                "categoryId": current_application_details.get("networkApplications")[0].get("categoryId"),
                "displayName": current_application_details.get("networkApplications")[0].get("displayName"),
                "helpString": required_application_details.get("helpstring") if "helpstring" in update_required_keys else current_application_details.get("networkApplications")[0].get("helpString"),
                "longDescription": required_application_details.get("description") if "description" in update_required_keys else current_application_details.get("networkApplications")[0].get("longDescription"),
                "name": current_application_details.get("networkApplications")[0].get("name"), 
                "popularity": current_application_details.get("networkApplications")[0].get("popularity"),
                "rank": required_application_details.get("rank") if "rank" in update_required_keys else current_application_details.get("networkApplications")[0].get("rank"),
                "selectorId": current_application_details.get("networkApplications")[0].get("selectorId"), 
                "trafficClass": required_application_details.get("traffic_class") if "traffic_class" in update_required_keys else current_application_details.get("networkApplications")[0].get("trafficClass"),
            }
        ],
        "parentScalableGroup": {
            "idRef": application_set_id
        },
        "qualifier": current_application_details.get("qualifier"),
        "scalableGroupExternalHandle": current_application_details.get("scalableGroupExternalHandle"),
        "scalableGroupType": current_application_details.get("scalableGroupType"),
        "type": current_application_details.get("type"),
    }
]

print(param)
