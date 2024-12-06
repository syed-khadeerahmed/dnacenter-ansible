want = {
  'queuing_profile_name': 'Asampleq2',
  'queuing_policy_description': 'sample 12234567876543q',
  'bandwidth_settings': {
    'is_common_between_all_interface_speeds': True,
    'interface_speed': 'ALL',
    'bandwidth_percentages': {
      'transactional_data': '5',
      'best_effort': '10',
      'voip_telephony': '15',
      'multimedia_streaming': '10',
      'real_time_interactive': '20',
      'multimedia_conferencing': '10',
      'signaling': '10',
      'scavenger': '5',
      'ops_admin_mgmt': '5',
      'broadcast_video': '2',
      'network_control': '3',
      'bulk_data': '5'
    }
  },
  'dscp_settings': {
    'multimedia_conferencing': '20',
    'ops_admin_mgmt': '23',
    'transactional_data': '28',
    'voip_telephony': '45',
    'multimedia_streaming': '27',
    'broadcast_video': '46',
    'network_control': '48',
    'best_effort': '0',
    'signaling': '4',
    'bulk_data': '10',
    'scavenger': '2',
    'real_time_interactive': '34'
  }
}

have = {'current_queuing_profile': [{'id': '7928ec20-244d-4694-b6ab-4b18a4ae71fe', 'instanceId': 330907317, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'createTime': 1733465660955, 'deployed': False, 'description': 'sample 12234567876543q', 'isSeeded': False, 'isStale': False, 'lastUpdateTime': 1733465660955, 'name': 'Asampleq2', 'namespace': '7928ec20-244d-4694-b6ab-4b18a4ae71fe', 'provisioningState': 'DEFINED', 'qualifier': 'application', 'resourceVersion': 0, 'targetIdList': [], 'type': 'contract', 'cfsChangeInfo': [], 'customProvisions': [], 'externalIntentSourceInfos': [], 'genId': 0, 'internal': False, 'isDeleted': False, 'iseReserved': False, 'pushed': False, 'clause': [{'id': '649eba3b-5bcc-4bfd-9c4c-541723ed6e17', 'instanceId': 330986164, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'priority': 1, 'type': 'BANDWIDTH', 'isCommonBetweenAllInterfaceSpeeds': True, 'interfaceSpeedBandwidthClauses': [{'id': 'f1ba0559-4a0e-41e5-ae4d-fbe964bf2638', 'instanceId': 334923690, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'interfaceSpeed': 'ALL', 'tcBandwidthSettings': [{'id': '4014c0be-fd4b-47fd-87c8-9c23b4b4bb51', 'instanceId': 403980788, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 20, 'trafficClass': 'REAL_TIME_INTERACTIVE', 'displayName': '0'}, {'id': '0fd4542e-ea8e-4eca-a357-81d51215f2c9', 'instanceId': 403980789, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 15, 'trafficClass': 'VOIP_TELEPHONY', 'displayName': '0'}, {'id': '976e5ecb-fcf2-42a0-b22d-23e7701acfe3', 'instanceId': 403980790, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 5, 'trafficClass': 'TRANSACTIONAL_DATA', 'displayName': '0'}, {'id': '612b4493-4ac9-4d42-b550-aee55774e8f4', 'instanceId': 403980791, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 5, 'trafficClass': 'SCAVENGER', 'displayName': '0'}, {'id': '7f3942b5-5bc4-4982-a91d-6c9ff9b6896d', 'instanceId': 403980796, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 10, 'trafficClass': 'BEST_EFFORT', 'displayName': '0'}, {'id': '4e4904d5-8d49-4b8d-bba5-57bfd2ae7940', 'instanceId': 403980797, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 2, 'trafficClass': 'BROADCAST_VIDEO', 'displayName': '0'}, {'id': '415f6306-b45d-49a5-86df-ea8d247ad284', 'instanceId': 403980798, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 10, 'trafficClass': 'MULTIMEDIA_CONFERENCING', 'displayName': '0'}, {'id': '5eccf79c-81a7-4246-b21e-168150daf7f3', 'instanceId': 403980799, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 10, 'trafficClass': 'MULTIMEDIA_STREAMING', 'displayName': '0'}, {'id': 'f1a93051-32eb-4f1a-a16c-e3538b935f93', 'instanceId': 403980792, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 3, 'trafficClass': 'NETWORK_CONTROL', 'displayName': '0'}, {'id': '537708aa-ba4f-4215-b8d1-771bf6c555d4', 'instanceId': 403980793, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 5, 'trafficClass': 'OPS_ADMIN_MGMT', 'displayName': '0'}, {'id': '9e7ad1cf-579a-4289-a78b-9fd7f69d6fa3', 'instanceId': 403980794, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 10, 'trafficClass': 'SIGNALING', 'displayName': '0'}, {'id': '0cd3587a-ac90-4151-973b-e4fb031d8213', 'instanceId': 403980795, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 5, 'trafficClass': 'BULK_DATA', 'displayName': '0'}], 'displayName': '0'}], 'displayName': '0'}, {'id': '76cf7587-2f4d-4d6a-b9dc-e8be08f4faf8', 'instanceId': 330986165, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'priority': 1, 'type': 'DSCP_CUSTOMIZATION', 'tcDscpSettings': [{'id': '52451cc7-0767-40df-a276-d6f04f85558b', 'instanceId': 330986922, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '20', 'trafficClass': 'MULTIMEDIA_CONFERENCING', 'displayName': '0'}, {'id': '688a42fe-0bf4-47e8-8697-ba9a62f60735', 'instanceId': 330986923, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '28', 'trafficClass': 'TRANSACTIONAL_DATA', 'displayName': '0'}, {'id': 'b52e007f-f759-4812-8588-f4eefc881f67', 'instanceId': 330986920, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '34', 'trafficClass': 'REAL_TIME_INTERACTIVE', 'displayName': '0'}, {'id': 'd5cc42b9-3f70-4171-a6ed-3844055cac2a', 'instanceId': 330986921, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '48', 'trafficClass': 'NETWORK_CONTROL', 'displayName': '0'}, {'id': 'f57198f3-0290-4e8f-80f1-10310b083073', 'instanceId': 330986926, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '4', 'trafficClass': 'SIGNALING', 'displayName': '0'}, {'id': '7ada76ed-33db-464c-9261-354ae8851e64', 'instanceId': 330986927, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '45', 'trafficClass': 'VOIP_TELEPHONY', 'displayName': '0'}, {'id': 'f7da2e64-ad3d-452a-95c4-ee0cd692032d', 'instanceId': 330986924, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '23', 'trafficClass': 'OPS_ADMIN_MGMT', 'displayName': '0'}, {'id': '07eb0441-463c-49af-bf3b-3876d929d994', 'instanceId': 330986925, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '10', 'trafficClass': 'BULK_DATA', 'displayName': '0'}, {'id': 'be7ccba3-c763-4de9-96e0-2090a9730c63', 'instanceId': 330986930, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '46', 'trafficClass': 'BROADCAST_VIDEO', 'displayName': '0'}, {'id': '144ee1c9-2c11-45fa-8c5f-508b88bf22b9', 'instanceId': 330986931, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '2', 'trafficClass': 'SCAVENGER', 'displayName': '0'}, {'id': 'd0701f12-ccb3-4ccc-a0f1-97efa7669d82', 'instanceId': 330986928, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '0', 'trafficClass': 'BEST_EFFORT', 'displayName': '0'}, {'id': '32e63093-5001-4835-be12-322d01fa857a', 'instanceId': 330986929, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '27', 'trafficClass': 'MULTIMEDIA_STREAMING', 'displayName': '0'}], 'displayName': '0'}], 'contractClassifier': [], 'displayName': '0'}], 'queuing_profile_exists': True} 


# Extract the details from required_queuing_profile_details
queuing_profile_details = want["application_queuing_details"]
existing_bandwidth_settings = {}
existing_dscp_settings = {}
new_bandwidth_settings = {}
new_dscp_settings = {}

# Extract existing bandwidth and DSCP settings with instance IDs
for profile in have["current_queuing_profile"]:
    if "clause" in profile:
        for clause in profile["clause"]:
            if clause["type"] == "BANDWIDTH":
                for interface_clause in clause["interfaceSpeedBandwidthClauses"]:
                    for bandwidth_setting in interface_clause["tcBandwidthSettings"]:
                        existing_bandwidth_settings[bandwidth_setting["trafficClass"]] = {
                            "bandwidthPercentage": bandwidth_setting["bandwidthPercentage"],
                            "instanceId": bandwidth_setting["instanceId"]
                        }
            elif clause["type"] == "DSCP_CUSTOMIZATION":
                for dscp_setting in clause["tcDscpSettings"]:
                    existing_dscp_settings[dscp_setting["trafficClass"]] = {
                        "dscp": dscp_setting["dscp"],
                        "instanceId": dscp_setting["instanceId"]
                    }

# Extract new bandwidth and DSCP settings from WANT
for profile in queuing_profile_details:
    if "bandwidth_settings" in profile:
        for traffic_class, bandwidth_percentage in profile["bandwidth_settings"]["bandwidth_percentages"].items():
            new_bandwidth_settings[traffic_class.upper()] = {
                "bandwidthPercentage": bandwidth_percentage
            }

    if "dscp_settings" in profile:
        for traffic_class, dscp_value in profile["dscp_settings"].items():
            new_dscp_settings[traffic_class.upper()] = {
                "dscp": dscp_value
            }

# Now compare the existing settings with the new settings from WANT and MAKE CHANGES if necessary
# Bandwidth settings comparison
for traffic_class, new_setting in new_bandwidth_settings.items():
    if traffic_class not in existing_bandwidth_settings or existing_bandwidth_settings[traffic_class]["bandwidthPercentage"] != new_setting["bandwidthPercentage"]:
        print(f"Updating bandwidth setting for {traffic_class}: {new_setting}")

# DSCP settings comparison
for traffic_class, new_setting in new_dscp_settings.items():
    if traffic_class not in existing_dscp_settings or existing_dscp_settings[traffic_class]["dscp"] != new_setting["dscp"]:
        print(f"Updating DSCP setting for {traffic_class}: {new_setting}")