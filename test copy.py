# Input data
required_queuing_profile_details = {'application_queuing_details': [{'queuing_profile_name': 'Asampleq2', 'queuing_policy_description': 'sample 12234567876543q', 'bandwidth_settings': {'is_common_between_all_interface_speeds': True, 'interface_speed': 'ALL', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '10', 'voip_telephony': '15', 'multimedia_streaming': '10', 'real_time_interactive': '20', 'multimedia_conferencing': '110', 'signaling': '10', 'scavenger': '5', 'ops_admin_mgmt': '5', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '5'}}, 'dscp_settings': {'multimedia_conferencing': '20', 'ops_admin_mgmt': '23', 'transactional_data': '28', 'voip_telephony': '45', 'multimedia_streaming': '27', 'broadcast_video': '46', 'network_control': '48', 'best_effort': '0', 'signaling': '4', 'bulk_data': '10', 'scavenger': '2', 'real_time_interactive': '34'}}], 'application_set_details': None, 'application_details': None} 


queuing_profile = {'current_queuing_profile': [{'id': '7928ec20-244d-4694-b6ab-4b18a4ae71fe', 'instanceId': 330907317, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'createTime': 1733465660955, 'deployed': False, 'description': 'sample 12234567876543q', 'isSeeded': False, 'isStale': False, 'lastUpdateTime': 1733465660955, 'name': 'Asampleq2', 'namespace': '7928ec20-244d-4694-b6ab-4b18a4ae71fe', 'provisioningState': 'DEFINED', 'qualifier': 'application', 'resourceVersion': 0, 'targetIdList': [], 'type': 'contract', 'cfsChangeInfo': [], 'customProvisions': [], 'externalIntentSourceInfos': [], 'genId': 0, 'internal': False, 'isDeleted': False, 'iseReserved': False, 'pushed': False, 'clause': [{'id': '649eba3b-5bcc-4bfd-9c4c-541723ed6e17', 'instanceId': 330986164, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'priority': 1, 'type': 'BANDWIDTH', 'isCommonBetweenAllInterfaceSpeeds': True, 'interfaceSpeedBandwidthClauses': [{'id': 'f1ba0559-4a0e-41e5-ae4d-fbe964bf2638', 'instanceId': 334923690, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'interfaceSpeed': 'ALL', 'tcBandwidthSettings': [{'id': '4014c0be-fd4b-47fd-87c8-9c23b4b4bb51', 'instanceId': 403980788, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 20, 'trafficClass': 'REAL_TIME_INTERACTIVE', 'displayName': '0'}, {'id': '0fd4542e-ea8e-4eca-a357-81d51215f2c9', 'instanceId': 403980789, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 15, 'trafficClass': 'VOIP_TELEPHONY', 'displayName': '0'}, {'id': '976e5ecb-fcf2-42a0-b22d-23e7701acfe3', 'instanceId': 403980790, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 5, 'trafficClass': 'TRANSACTIONAL_DATA', 'displayName': '0'}, {'id': '612b4493-4ac9-4d42-b550-aee55774e8f4', 'instanceId': 403980791, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 5, 'trafficClass': 'SCAVENGER', 'displayName': '0'}, {'id': '7f3942b5-5bc4-4982-a91d-6c9ff9b6896d', 'instanceId': 403980796, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 10, 'trafficClass': 'BEST_EFFORT', 'displayName': '0'}, {'id': '4e4904d5-8d49-4b8d-bba5-57bfd2ae7940', 'instanceId': 403980797, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 2, 'trafficClass': 'BROADCAST_VIDEO', 'displayName': '0'}, {'id': '415f6306-b45d-49a5-86df-ea8d247ad284', 'instanceId': 403980798, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 10, 'trafficClass': 'MULTIMEDIA_CONFERENCING', 'displayName': '0'}, {'id': '5eccf79c-81a7-4246-b21e-168150daf7f3', 'instanceId': 403980799, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 10, 'trafficClass': 'MULTIMEDIA_STREAMING', 'displayName': '0'}, {'id': 'f1a93051-32eb-4f1a-a16c-e3538b935f93', 'instanceId': 403980792, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 3, 'trafficClass': 'NETWORK_CONTROL', 'displayName': '0'}, {'id': '537708aa-ba4f-4215-b8d1-771bf6c555d4', 'instanceId': 403980793, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 5, 'trafficClass': 'OPS_ADMIN_MGMT', 'displayName': '0'}, {'id': '9e7ad1cf-579a-4289-a78b-9fd7f69d6fa3', 'instanceId': 403980794, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 10, 'trafficClass': 'SIGNALING', 'displayName': '0'}, {'id': '0cd3587a-ac90-4151-973b-e4fb031d8213', 'instanceId': 403980795, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 5, 'trafficClass': 'BULK_DATA', 'displayName': '0'}], 'displayName': '0'}], 'displayName': '0'}, {'id': '76cf7587-2f4d-4d6a-b9dc-e8be08f4faf8', 'instanceId': 330986165, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'priority': 1, 'type': 'DSCP_CUSTOMIZATION', 'tcDscpSettings': [{'id': '52451cc7-0767-40df-a276-d6f04f85558b', 'instanceId': 330986922, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '20', 'trafficClass': 'MULTIMEDIA_CONFERENCING', 'displayName': '0'}, {'id': '688a42fe-0bf4-47e8-8697-ba9a62f60735', 'instanceId': 330986923, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '28', 'trafficClass': 'TRANSACTIONAL_DATA', 'displayName': '0'}, {'id': 'b52e007f-f759-4812-8588-f4eefc881f67', 'instanceId': 330986920, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '34', 'trafficClass': 'REAL_TIME_INTERACTIVE', 'displayName': '0'}, {'id': 'd5cc42b9-3f70-4171-a6ed-3844055cac2a', 'instanceId': 330986921, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '48', 'trafficClass': 'NETWORK_CONTROL', 'displayName': '0'}, {'id': 'f57198f3-0290-4e8f-80f1-10310b083073', 'instanceId': 330986926, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '4', 'trafficClass': 'SIGNALING', 'displayName': '0'}, {'id': '7ada76ed-33db-464c-9261-354ae8851e64', 'instanceId': 330986927, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '45', 'trafficClass': 'VOIP_TELEPHONY', 'displayName': '0'}, {'id': 'f7da2e64-ad3d-452a-95c4-ee0cd692032d', 'instanceId': 330986924, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '23', 'trafficClass': 'OPS_ADMIN_MGMT', 'displayName': '0'}, {'id': '07eb0441-463c-49af-bf3b-3876d929d994', 'instanceId': 330986925, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '10', 'trafficClass': 'BULK_DATA', 'displayName': '0'}, {'id': 'be7ccba3-c763-4de9-96e0-2090a9730c63', 'instanceId': 330986930, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '46', 'trafficClass': 'BROADCAST_VIDEO', 'displayName': '0'}, {'id': '144ee1c9-2c11-45fa-8c5f-508b88bf22b9', 'instanceId': 330986931, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '2', 'trafficClass': 'SCAVENGER', 'displayName': '0'}, {'id': 'd0701f12-ccb3-4ccc-a0f1-97efa7669d82', 'instanceId': 330986928, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '0', 'trafficClass': 'BEST_EFFORT', 'displayName': '0'}, {'id': '32e63093-5001-4835-be12-322d01fa857a', 'instanceId': 330986929, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '27', 'trafficClass': 'MULTIMEDIA_STREAMING', 'displayName': '0'}], 'displayName': '0'}], 'contractClassifier': [], 'displayName': '0'}], 'queuing_profile_exists': True} 

existing_bandwidth_settings = {}
existing_dscp_settings = {}

new_bandwidth_settings = {}
new_dscp_settings = {}

# Extract the details from required_queuing_profile_details
queuing_profile_details = required_queuing_profile_details["application_queuing_details"]

for profile in queuing_profile_details:
    if "bandwidth_settings" in profile:
        for traffic_class, bandwidth_percentage in profile["bandwidth_settings"]["bandwidth_percentages"].items():
            new_bandwidth_settings[traffic_class.upper()] = {  # Ensure traffic class is upper case
                "bandwidthPercentage": bandwidth_percentage
            }

    if "dscp_settings" in profile:
        for traffic_class, dscp_value in profile["dscp_settings"].items():
            new_dscp_settings[traffic_class.upper()] = {  # Ensure traffic class is upper case
                "dscp": dscp_value
            }

# Compare and update existing bandwidth settings if any changes
updated_bandwidth_settings = False
for traffic_class, new_bandwidth in new_bandwidth_settings.items():
    if traffic_class not in existing_bandwidth_settings or existing_bandwidth_settings[traffic_class]["bandwidthPercentage"] != new_bandwidth["bandwidthPercentage"]:
        # Update the bandwidth settings and retain the instanceId from the existing settings
        existing_bandwidth_settings[traffic_class] = {
            "bandwidthPercentage": new_bandwidth["bandwidthPercentage"],
            "instanceId": existing_bandwidth_settings.get(traffic_class, {}).get("instanceId", None)
        }
        updated_bandwidth_settings = True

# DSCP settings comparison (no update needed in this case based on your expected output)
updated_dscp_settings = False
for traffic_class, new_dscp in new_dscp_settings.items():
    if traffic_class not in existing_dscp_settings or existing_dscp_settings[traffic_class]["dscp"] != new_dscp["dscp"]:
        # Update the DSCP settings and retain the instanceId from the existing settings
        existing_dscp_settings[traffic_class] = {
            "dscp": new_dscp["dscp"],
            "instanceId": existing_dscp_settings.get(traffic_class, {}).get("instanceId", None)
        }
        updated_dscp_settings = True

# Output the updated dictionaries
if updated_bandwidth_settings:
    print("Updated Bandwidth Settings:", existing_bandwidth_settings)
else:
    print("No changes to Bandwidth Settings.")

if updated_dscp_settings:
    print("Updated DSCP Settings:", existing_dscp_settings)
else:
    print("No changes to DSCP Settings.")


# output :
# Existing Bandwidth Settings: {'BROADCAST_VIDEO': {'bandwidthPercentage': 2, 'instanceId': 334925542}, 'NETWORK_CONTROL': {'bandwidthPercentage': 3, 'instanceId': 334925543}, 'MULTIMEDIA_CONFERENCING': {'bandwidthPercentage': 10, 'instanceId': 334925540}, 'SIGNALING': {'bandwidthPercentage': 10, 'instanceId': 334925541}, 'TRANSACTIONAL_DATA': {'bandwidthPercentage': 10, 'instanceId': 334925538}, 'BULK_DATA': {'bandwidthPercentage': 5, 'instanceId': 334925539}, 'REAL_TIME_INTERACTIVE': {'bandwidthPercentage': 20, 'instanceId': 334925548}, 'MULTIMEDIA_STREAMING': {'bandwidthPercentage': 11, 'instanceId': 334925549}, 'SCAVENGER': {'bandwidthPercentage': 5, 'instanceId': 334925546}, 'VOIP_TELEPHONY': {'bandwidthPercentage': 15, 'instanceId': 334925547}, 'BEST_EFFORT': {'bandwidthPercentage': 10, 'instanceId': 334925544}, 'OPS_ADMIN_MGMT': {'bandwidthPercentage': 5, 'instanceId': 334925545}}
# Existing DSCP Settings: {'SIGNALING': {'dscp': '4', 'instanceId': 330986874}, 'NETWORK_CONTROL': {'dscp': '48', 'instanceId': 330986875}, 'MULTIMEDIA_STREAMING': {'dscp': '27', 'instanceId': 330986872}, 'OPS_ADMIN_MGMT': {'dscp': '23', 'instanceId': 330986873}, 'TRANSACTIONAL_DATA': {'dscp': '28', 'instanceId': 330986878}, 'BULK_DATA': {'dscp': '10', 'instanceId': 330986879}, 'MULTIMEDIA_CONFERENCING': {'dscp': '20', 'instanceId': 330986876}, 'VOIP_TELEPHONY': {'dscp': '45', 'instanceId': 330986877}, 'REAL_TIME_INTERACTIVE': {'dscp': '34', 'instanceId': 330986882}, 'BEST_EFFORT': {'dscp': '0', 'instanceId': 330986883}, 'SCAVENGER': {'dscp': '2', 'instanceId': 330986880}, 'BROADCAST_VIDEO': {'dscp': '46', 'instanceId': 330986881}}
# New Bandwidth Settings: {'transactional_data': {'bandwidthPercentage': '11'}, 'best_effort': {'bandwidthPercentage': '10'}, 'voip_telephony': {'bandwidthPercentage': '15'}, 'multimedia_streaming': {'bandwidthPercentage': '11'}, 'real_time_interactive': {'bandwidthPercentage': '20'}, 'multimedia_conferencing': {'bandwidthPercentage': '10'}, 'signaling': {'bandwidthPercentage': '10'}, 'scavenger': {'bandwidthPercentage': '5'}, 'ops_admin_mgmt': {'bandwidthPercentage': '5'}, 'broadcast_video': {'bandwidthPercentage': '2'}, 'network_control': {'bandwidthPercentage': '3'}, 'bulk_data': {'bandwidthPercentage': '5'}}
# New DSCP Settings: {'multimedia_conferencing': {'dscp': '20'}, 'ops_admin_mgmt': {'dscp': '23'}, 'transactional_data': {'dscp': '28'}, 'voip_telephony': {'dscp': '45'}, 'multimedia_streaming': {'dscp': '27'}, 'broadcast_video': {'dscp': '46'}, 'network_control': {'dscp': '48'}, 'best_effort': {'dscp': '0'}, 'signaling': {'dscp': '4'}, 'bulk_data': {'dscp': '10'}, 'scavenger': {'dscp': '2'}, 'real_time_interactive': {'dscp': '34'}}

# expected output:
# updated Bandwidth Settings: {'BROADCAST_VIDEO': {'bandwidthPercentage': 2, 'instanceId': 334925542}, 'NETWORK_CONTROL': {'bandwidthPercentage': 3, 'instanceId': 334925543}, 'MULTIMEDIA_CONFERENCING': {'bandwidthPercentage': 10, 'instanceId': 334925540}, 'SIGNALING': {'bandwidthPercentage': 10, 'instanceId': 334925541}, 'TRANSACTIONAL_DATA': {'bandwidthPercentage': 11, 'instanceId': 334925538}, 'BULK_DATA': {'bandwidthPercentage': 5, 'instanceId': 334925539}, 'REAL_TIME_INTERACTIVE': {'bandwidthPercentage': 20, 'instanceId': 334925548}, 'MULTIMEDIA_STREAMING': {'bandwidthPercentage': 11, 'instanceId': 334925549}, 'SCAVENGER': {'bandwidthPercentage': 5, 'instanceId': 334925546}, 'VOIP_TELEPHONY': {'bandwidthPercentage': 15, 'instanceId': 334925547}, 'BEST_EFFORT': {'bandwidthPercentage': 10, 'instanceId': 334925544}, 'OPS_ADMIN_MGMT': {'bandwidthPercentage': 5, 'instanceId': 334925545}}
# updated DSCP Settings: {'SIGNALING': {'dscp': '4', 'instanceId': 330986874}, 'NETWORK_CONTROL': {'dscp': '48', 'instanceId': 330986875}, 'MULTIMEDIA_STREAMING': {'dscp': '27', 'instanceId': 330986872}, 'OPS_ADMIN_MGMT': {'dscp': '23', 'instanceId': 330986873}, 'TRANSACTIONAL_DATA': {'dscp': '28', 'instanceId': 330986878}, 'BULK_DATA': {'dscp': '10', 'instanceId': 330986879}, 'MULTIMEDIA_CONFERENCING': {'dscp': '20', 'instanceId': 330986876}, 'VOIP_TELEPHONY': {'dscp': '45', 'instanceId': 330986877}, 'REAL_TIME_INTERACTIVE': {'dscp': '34', 'instanceId': 330986882}, 'BEST_EFFORT': {'dscp': '0', 'instanceId': 330986883}, 'SCAVENGER': {'dscp': '2', 'instanceId': 330986880}, 'BROADCAST_VIDEO': {'dscp': '46', 'instanceId': 330986881}}

# as there is some changes between Existing Bandwidth Settings and New Bandwidth Settings but no update is required so using the Existing DSCP Settings

# Initialize dictionaries to store new bandwidth and DSCP settings

# Initialize existing and new settings
existing_bandwidth_settings = {

}

existing_dscp_settings = {

}

new_bandwidth_settings = {}
new_dscp_settings = {}

# Extract new settings from `required_queuing_profile_details`
queuing_profile_details = required_queuing_profile_details["application_queuing_details"]

for profile in queuing_profile_details:
    if "bandwidth_settings" in profile:
        for traffic_class, bandwidth_percentage in profile["bandwidth_settings"]["bandwidth_percentages"].items():
            new_bandwidth_settings[traffic_class.upper()] = {
                "bandwidthPercentage": int(bandwidth_percentage)
            }

    if "dscp_settings" in profile:
        for traffic_class, dscp_value in profile["dscp_settings"].items():
            new_dscp_settings[traffic_class.upper()] = {
                "dscp": int(dscp_value)
            }

# Update existing bandwidth settings
updated_bandwidth_settings = False
for traffic_class, new_bandwidth in new_bandwidth_settings.items():
    if (
        traffic_class not in existing_bandwidth_settings or 
        existing_bandwidth_settings[traffic_class]["bandwidthPercentage"] != new_bandwidth["bandwidthPercentage"]
    ):
        # Update with new bandwidth percentage, retain instanceId if exists
        existing_bandwidth_settings[traffic_class] = {
            "bandwidthPercentage": new_bandwidth["bandwidthPercentage"],
            "instanceId": existing_bandwidth_settings.get(traffic_class, {}).get("instanceId", None),
        }
        updated_bandwidth_settings = True

# Update existing DSCP settings
updated_dscp_settings = False
for traffic_class, new_dscp in new_dscp_settings.items():
    if (
        traffic_class not in existing_dscp_settings or 
        existing_dscp_settings[traffic_class]["dscp"] != new_dscp["dscp"]
    ):
        # Update with new DSCP value, retain instanceId if exists
        existing_dscp_settings[traffic_class] = {
            "dscp": new_dscp["dscp"],
            "instanceId": existing_dscp_settings.get(traffic_class, {}).get("instanceId", None),
        }
        updated_dscp_settings = True

# Print final settings and flags for updates
print("Updated Bandwidth Settings:", updated_bandwidth_settings)
print("Updated DSCP Settings:", updated_dscp_settings)
print("Final Bandwidth Settings:", existing_bandwidth_settings)
print("Final DSCP Settings:", existing_dscp_settings)
