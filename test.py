# config = {'queuing_profile_name': 'newprofile15', 'queuing_policy_description': 'sample desc', 'type': ['bandwidth'], 'bandwidth_settings': {'is_common_between_all_interface_speeds': False, 'interface_speed_settings': [{'interface_speed': 'HUNDRED_GBPS', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '10', 'voip_telephony': '15', 'multimedia_streaming': '10', 'real_time_interactive': '20', 'multimedia_conferencing': '10', 'signaling': '10', 'scavenger': '5', 'ops_admin_mgmt': '5', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '5'}}, {'interface_speed': 'TEN_GBPS', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '10', 'voip_telephony': '15', 'multimedia_streaming': '10', 'real_time_interactive': '20', 'multimedia_conferencing': '10', 'signaling': '10', 'scavenger': '5', 'ops_admin_mgmt': '5', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '5'}}, {'interface_speed': 'ONE_GBPS', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '10', 'voip_telephony': '15', 'multimedia_streaming': '10', 'real_time_interactive': '20', 'multimedia_conferencing': '10', 'signaling': '10', 'scavenger': '5', 'ops_admin_mgmt': '5', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '5'}}, {'interface_speed': 'HUNDRED_MBPS', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '10', 'voip_telephony': '15', 'multimedia_streaming': '10', 'real_time_interactive': '20', 'multimedia_conferencing': '10', 'signaling': '10', 'scavenger': '5', 'ops_admin_mgmt': '5', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '5'}}, {'interface_speed': 'TEN_MBPS', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '10', 'voip_telephony': '15', 'multimedia_streaming': '10', 'real_time_interactive': '20', 'multimedia_conferencing': '10', 'signaling': '10', 'scavenger': '5', 'ops_admin_mgmt': '5', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '5'}}, {'interface_speed': 'ONE_MBPS', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '10', 'voip_telephony': '15', 'multimedia_streaming': '10', 'real_time_interactive': '20', 'multimedia_conferencing': '10', 'signaling': '10', 'scavenger': '5', 'ops_admin_mgmt': '5', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '5'}}]}} 


# def map_config_to_payload(config):
#   payload = {
#     "name": config['queuing_profile_name'],
#     "description": config['queuing_policy_description'],
#     "clause": [
#       {
#         "type": config['type'][0].upper(),
#         "isCommonBetweenAllInterfaceSpeeds": config['bandwidth_settings']['is_common_between_all_interface_speeds'],
#         "interfaceSpeedBandwidthClauses": []
#       }
#     ]
#   }

#   for interface in config['bandwidth_settings']['interface_speed_settings']:
#     interface_speed_clause = {
#       "interfaceSpeed": interface['interface_speed'],
#       "tcBandwidthSettings": [
#         {
#           "trafficClass": key.upper(),
#           "bandwidthPercentage": int(value)
#         }
#         for key, value in interface['bandwidth_percentages'].items()
#       ]
#     }
#     payload["clause"][0]["interfaceSpeedBandwidthClauses"].append(interface_speed_clause)

#   return [payload]

# # Example usage
# transformed_payload = map_config_to_payload(config)
# print(transformed_payload)


# config = {
#     'queuing_profile_name': 'newprofile19',
#     'queuing_policy_description': 'sample desc',
#     'type': ['bandwidth'],
#     'bandwidth_settings': {
#         'is_common_between_all_interface_speeds': False,
#         'interface_speed_settings': [
#             {'interface_speed': 'HUNDRED_GBPS', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '10', 'voip_telephony': '20', 'multimedia_streaming': '5', 'real_time_interactive': '20', 'multimedia_conferencing': '10', 'signaling': '10', 'scavenger': '5', 'ops_admin_mgmt': '5', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '5'}},
#             {'interface_speed': 'TEN_GBPS', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '15', 'voip_telephony': '25', 'multimedia_streaming': '5', 'real_time_interactive': '20', 'multimedia_conferencing': '5', 'signaling': '5', 'scavenger': '5', 'ops_admin_mgmt': '5', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '5'}},
#             {'interface_speed': 'ONE_GBPS', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '10', 'voip_telephony': '15', 'multimedia_streaming': '10', 'real_time_interactive': '20', 'multimedia_conferencing': '10', 'signaling': '10', 'scavenger': '5', 'ops_admin_mgmt': '5', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '5'}},
#             {'interface_speed': 'HUNDRED_MBPS', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '10', 'voip_telephony': '5', 'multimedia_streaming': '15', 'real_time_interactive': '25', 'multimedia_conferencing': '10', 'signaling': '10', 'scavenger': '5', 'ops_admin_mgmt': '5', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '5'}},
#             {'interface_speed': 'TEN_MBPS', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '10', 'voip_telephony': '15', 'multimedia_streaming': '10', 'real_time_interactive': '20', 'multimedia_conferencing': '10', 'signaling': '10', 'scavenger': '5', 'ops_admin_mgmt': '5', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '5'}},
#             {'interface_speed': 'ONE_MBPS', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '5', 'voip_telephony': '25', 'multimedia_streaming': '10', 'real_time_interactive': '20', 'multimedia_conferencing': '5', 'signaling': '10', 'scavenger': '5', 'ops_admin_mgmt': '5', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '5'}}
#         ]
#     }
# }

# for interface in config['bandwidth_settings']['interface_speed_settings']:
#     total_percentage = sum(int(value) for value in interface['bandwidth_percentages'].values())
#     if total_percentage != 100:
#         print(f"fail at interface speed: {interface['interface_speed']} (Total: {total_percentage}%)")

def expand_comma_separated_speeds(data):
    expanded_settings = []

    # Loop through each entry in the interface_speed_settings
    for entry in data['bandwidth_settings']['interface_speed_settings']:
        # Split the 'interface_speed' by commas if there are multiple speeds
        speeds = entry['interface_speed'].split(',')
        
        # For each speed, create a new entry with the same bandwidth_percentages
        for speed in speeds:
            new_entry = entry.copy()  # Copy the original entry
            new_entry['interface_speed'] = speed.strip()  # Clean up any spaces
            expanded_settings.append(new_entry)
    
    # Update the original data with the expanded interface_speed_settings
    data['bandwidth_settings']['interface_speed_settings'] = expanded_settings
    return data

# Original data
data = {
    'queuing_profile_name': 'newprofile20',
    'queuing_policy_description': 'sample desc',
    'type': ['bandwidth'],
    'bandwidth_settings': {
        'is_common_between_all_interface_speeds': False,
        'interface_speed_settings': [
            {'interface_speed': 'HUNDRED_GBPS', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '10', 'voip_telephony': '20', 'multimedia_streaming': '5', 'real_time_interactive': '20', 'multimedia_conferencing': '10', 'signaling': '10', 'scavenger': '5', 'ops_admin_mgmt': '5', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '5'}},
            {'interface_speed': 'TEN_GBPS', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '5', 'voip_telephony': '25', 'multimedia_streaming': '5', 'real_time_interactive': '20', 'multimedia_conferencing': '5', 'signaling': '6', 'scavenger': '5', 'ops_admin_mgmt': '4', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '15'}},
            {'interface_speed': 'ONE_GBPS', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '10', 'voip_telephony': '15', 'multimedia_streaming': '10', 'real_time_interactive': '20', 'multimedia_conferencing': '10', 'signaling': '10', 'scavenger': '5', 'ops_admin_mgmt': '5', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '5'}},
            {'interface_speed': 'HUNDRED_MBPS', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '10', 'voip_telephony': '5', 'multimedia_streaming': '15', 'real_time_interactive': '25', 'multimedia_conferencing': '10', 'signaling': '10', 'scavenger': '5', 'ops_admin_mgmt': '5', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '5'}},
            {'interface_speed': 'TEN_MBPS,ONE_MBPS', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '10', 'voip_telephony': '15', 'multimedia_streaming': '10', 'real_time_interactive': '20', 'multimedia_conferencing': '10', 'signaling': '10', 'scavenger': '5', 'ops_admin_mgmt': '5', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '5'}}
        ]
    }
}

# Expand the interface speeds from comma-separated values
expanded_data = expand_comma_separated_speeds(data)

# Output the modified data
print(expanded_data)
