
new_queuing_profile_details = {'queuing_profile_name': 'newprofile20', 'queuing_policy_description': 'sample desc', 'type': ['bandwidth'], 'bandwidth_settings': {'is_common_between_all_interface_speeds': False, 'interface_speed_settings': [{'interface_speed': 'HUNDRED_GBPS', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '10', 'voip_telephony': '20', 'multimedia_streaming': '5', 'real_time_interactive': '20', 'multimedia_conferencing': '10', 'signaling': '10', 'scavenger': '5', 'ops_admin_mgmt': '5', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '5'}}, {'interface_speed': 'TEN_GBPS', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '5', 'voip_telephony': '25', 'multimedia_streaming': '5', 'real_time_interactive': '20', 'multimedia_conferencing': '5', 'signaling': '6', 'scavenger': '5', 'ops_admin_mgmt': '4', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '15'}}, {'interface_speed': 'ONE_GBPS', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '10', 'voip_telephony': '15', 'multimedia_streaming': '10', 'real_time_interactive': '20', 'multimedia_conferencing': '10', 'signaling': '10', 'scavenger': '5', 'ops_admin_mgmt': '5', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '5'}}, {'interface_speed': 'HUNDRED_MBPS', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '10', 'voip_telephony': '5', 'multimedia_streaming': '15', 'real_time_interactive': '25', 'multimedia_conferencing': '10', 'signaling': '10', 'scavenger': '5', 'ops_admin_mgmt': '5', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '5'}}, {'interface_speed': 'TEN_MBPS,ONE_MBPS', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '10', 'voip_telephony': '15', 'multimedia_streaming': '10', 'real_time_interactive': '20', 'multimedia_conferencing': '10', 'signaling': '10', 'scavenger': '5', 'ops_admin_mgmt': '5', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '5'}}]}} 


param = {
    "name": new_queuing_profile_details['queuing_profile_name'],
    "description": new_queuing_profile_details['queuing_policy_description'],
    "clause": [
        {
            "type": new_queuing_profile_details['type'][0].upper(),
            "isCommonBetweenAllInterfaceSpeeds": new_queuing_profile_details['bandwidth_settings']['is_common_between_all_interface_speeds'],
            "interfaceSpeedBandwidthClauses": []
        }
    ]
}

for interface in new_queuing_profile_details['bandwidth_settings']['interface_speed_settings']:
    # Split the comma-separated interface speeds
    interface_speeds = interface['interface_speed'].split(',')
    for speed in interface_speeds:
        # Create the interface speed clause
        interface_speed_clause = {
            "interfaceSpeed": speed.strip(),  # Strip any extra spaces
            "tcBandwidthSettings": [
                {
                    "trafficClass": key.upper(),
                    "bandwidthPercentage": int(value)
                }
                for key, value in interface['bandwidth_percentages'].items()
            ]
        }
        # Append the clause to the main structure
        param["clause"][0]["interfaceSpeedBandwidthClauses"].append(interface_speed_clause)

# Print or use the final param as needed
import json
print(json.dumps(param, indent=2))
