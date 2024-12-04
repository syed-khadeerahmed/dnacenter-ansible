# Input data
required_queuing_profile_details = {'application_queuing_details': [{'queuing_profile_name': 'Asampleqdscp1', 'queuing_profile_new_name': 'Asampleq10', 'queuing_policy_description': 'sample 12234567876543q', 'type': ['dscp'], 'dscp_settings': {'multimedia_conferencing': '20', 'ops_admin_mgmt': '23', 'transactional_data': '28', 'voip_telephony': '45', 'multimedia_streaming': '27', 'broadcast_video': '46', 'network_control': '48', 'best_effort': '0', 'signaling': '4', 'bulk_data': '10', 'scavenger': '2', 'real_time_interactive': '34'}}], 'application_set_details': None} 


queuing_profile = {'current_queuing_profile': [{'id': 'd880ef32-0fd4-41f1-a7b7-ffb7b83c2720', 'instanceId': 73098028, 'instanceCreatedOn': 1732618419135, 'instanceUpdatedOn': 1732618419135, 'instanceVersion': 0, 'createTime': 1732618419126, 'deployed': False, 'description': 'sample 12234567876543q', 'isSeeded': False, 'isStale': False, 'lastUpdateTime': 1732618419126, 'name': 'Asampleqdscp1', 'namespace': 'd880ef32-0fd4-41f1-a7b7-ffb7b83c2720', 'provisioningState': 'DEFINED', 'qualifier': 'application', 'resourceVersion': 0, 'targetIdList': [], 'type': 'contract', 'cfsChangeInfo': [], 'customProvisions': [], 'externalIntentSourceInfos': [], 'genId': 0, 'internal': False, 'isDeleted': False, 'iseReserved': False, 'pushed': False, 'clause': [{'id': 'd865fa9f-81db-4c61-967f-ea415a1d761a', 'instanceId': 73099030, 'instanceCreatedOn': 1732618419135, 'instanceUpdatedOn': 1732618419135, 'instanceVersion': 0, 'priority': 1, 'type': 'DSCP_CUSTOMIZATION', 'tcDscpSettings': [{'id': '69e55d81-5ae4-46b5-bdd2-0369a9c93ada', 'instanceId': 73110072, 'instanceCreatedOn': 1732618419135, 'instanceUpdatedOn': 1732618419135, 'instanceVersion': 0, 'dscp': '4', 'trafficClass': 'SIGNALING', 'displayName': '0'}, {'id': '6bbaa460-e048-46c1-8763-619bff52aa8b', 'instanceId': 73110063, 'instanceCreatedOn': 1732618419135, 'instanceUpdatedOn': 1732618419135, 'instanceVersion': 0, 'dscp': '45', 'trafficClass': 'VOIP_TELEPHONY', 'displayName': '0'}, {'id': '1a7c853e-2952-4a22-9dde-16183c01552e', 'instanceId': 73110062, 'instanceCreatedOn': 1732618419135, 'instanceUpdatedOn': 1732618419135, 'instanceVersion': 0, 'dscp': '34', 'trafficClass': 'REAL_TIME_INTERACTIVE', 'displayName': '0'}, {'id': '21aac420-0933-4d9c-8fe2-8a20f21c5f2b', 'instanceId': 73110061, 'instanceCreatedOn': 1732618419135, 'instanceUpdatedOn': 1732618419135, 'instanceVersion': 0, 'dscp': '23', 'trafficClass': 'OPS_ADMIN_MGMT', 'displayName': '0'}, {'id': 'f204862d-e143-45a8-9c34-4bfb59e9c291', 'instanceId': 73110067, 'instanceCreatedOn': 1732618419135, 'instanceUpdatedOn': 1732618419135, 'instanceVersion': 0, 'dscp': '27', 'trafficClass': 'MULTIMEDIA_STREAMING', 'displayName': '0'}, {'id': 'ad35a948-02e4-4701-93e1-838a8d5f7c57', 'instanceId': 73110066, 'instanceCreatedOn': 1732618419135, 'instanceUpdatedOn': 1732618419135, 'instanceVersion': 0, 'dscp': '48', 'trafficClass': 'NETWORK_CONTROL', 'displayName': '0'}, {'id': 'fabddbcb-a4b7-4f9f-9f0b-787ca5646811', 'instanceId': 73110065, 'instanceCreatedOn': 1732618419135, 'instanceUpdatedOn': 1732618419135, 'instanceVersion': 0, 'dscp': '28', 'trafficClass': 'TRANSACTIONAL_DATA', 'displayName': '0'}, {'id': '0cd5dc30-8daa-4a43-af6a-6d4417ca4bd4', 'instanceId': 73110064, 'instanceCreatedOn': 1732618419135, 'instanceUpdatedOn': 1732618419135, 'instanceVersion': 0, 'dscp': '0', 'trafficClass': 'BEST_EFFORT', 'displayName': '0'}, {'id': '9bf336af-89ec-4f07-99e7-bcc493c38162', 'instanceId': 73110071, 'instanceCreatedOn': 1732618419135, 'instanceUpdatedOn': 1732618419135, 'instanceVersion': 0, 'dscp': '2', 'trafficClass': 'SCAVENGER', 'displayName': '0'}, {'id': 'beb533c4-7f7a-4554-b688-4eeed9819aeb', 'instanceId': 73110070, 'instanceCreatedOn': 1732618419135, 'instanceUpdatedOn': 1732618419135, 'instanceVersion': 0, 'dscp': '10', 'trafficClass': 'BULK_DATA', 'displayName': '0'}, {'id': 'fc0b7b18-b1d3-4719-9dd6-1138e27c444c', 'instanceId': 73110069, 'instanceCreatedOn': 1732618419135, 'instanceUpdatedOn': 1732618419135, 'instanceVersion': 0, 'dscp': '20', 'trafficClass': 'MULTIMEDIA_CONFERENCING', 'displayName': '0'}, {'id': 'a55a5fa5-e0ac-4f56-9baf-16948f8985cd', 'instanceId': 73110068, 'instanceCreatedOn': 1732618419135, 'instanceUpdatedOn': 1732618419135, 'instanceVersion': 0, 'dscp': '46', 'trafficClass': 'BROADCAST_VIDEO', 'displayName': '0'}], 'displayName': '0'}], 'contractClassifier': [], 'displayName': '0'}], 'queuing_profile_exists': True} 



# Initialize dictionaries to store existing bandwidth and DSCP settings
existing_bandwidth_settings = {}
existing_dscp_settings = {}

# Access the queuing profile's clauses
queuing_profile_clauses = queuing_profile["current_queuing_profile"][0]["clause"]

# Extract BANDWIDTH and DSCP_CUSTOMIZATION settings
for clause in queuing_profile_clauses:
    if clause["type"] == "BANDWIDTH":
        for interface_speed_clause in clause.get("interfaceSpeedBandwidthClauses", []):
            for bandwidth_setting in interface_speed_clause.get("tcBandwidthSettings", []):
                traffic_class = bandwidth_setting["trafficClass"]
                existing_bandwidth_settings[traffic_class] = {
                    "bandwidthPercentage": bandwidth_setting["bandwidthPercentage"],
                    "instanceId": bandwidth_setting["instanceId"],
                }
    elif clause["type"] == "DSCP_CUSTOMIZATION":
        for dscp_setting in clause.get("tcDscpSettings", []):
            traffic_class = dscp_setting["trafficClass"]
            existing_dscp_settings[traffic_class] = {
                "dscp": dscp_setting["dscp"],
                "instanceId": dscp_setting["instanceId"],
            }

# Extract required DSCP settings
new_dscp_settings = {}
queuing_profile_details = required_queuing_profile_details.get("application_queuing_details", [])

for profile in queuing_profile_details:
    for traffic_class, dscp_value in profile.get("dscp_settings", {}).items():
        new_dscp_settings[traffic_class.upper()] = {
            "dscp": dscp_value
        }

# Compare and update DSCP settings
updated_dscp_settings = False
for traffic_class, new_dscp in new_dscp_settings.items():
    if traffic_class not in existing_dscp_settings or str(existing_dscp_settings[traffic_class]["dscp"]) != new_dscp["dscp"]:
        existing_dscp_settings[traffic_class] = {
            "dscp": new_dscp["dscp"],
            "instanceId": existing_dscp_settings.get(traffic_class, {}).get("instanceId", None),
        }
        updated_dscp_settings = True

# Output the updated DSCP settings
if updated_dscp_settings:
    print("Updated DSCP Settings:", existing_dscp_settings)
else:
    print("No changes to DSCP Settings.")
