new_queuing_profile_details = {
    'queuing_profile_name': 'sampleq2',
    'queuing_policy_description': 'sample 12234567876543q',
    'type': ['bandwidth', 'dscp'],
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
        'multimedia_conferencing': '16',
        'ops_admin_mgmt': '20',
        'transactional_data': '28',
        'voip_telephony': '46',
        'multimedia_streaming': '26',
        'broadcast_video': '40',
        'network_control': '49',
        'best_effort': '0',
        'signaling': '4',
        'bulk_data': '10',
        'scavenger': '2',
        'real_time_interactive': '34'
    }
}

param = {
    "name": new_queuing_profile_details.get('queuing_profile_name', ''),
    "description": new_queuing_profile_details.get('queuing_policy_description', ''),
    "clause": []
}

if 'bandwidth' in new_queuing_profile_details['type']:
    bandwidth_clause = {
        "type": "BANDWIDTH",
        "isCommonBetweenAllInterfaceSpeeds": new_queuing_profile_details['bandwidth_settings'].get(
            'is_common_between_all_interface_speeds', False
        ),
        "interfaceSpeedBandwidthClauses": [
            {
                "interfaceSpeed": new_queuing_profile_details['bandwidth_settings'].get('interface_speed', ''),
                "tcBandwidthSettings": [
                    {
                        "trafficClass": key.upper(),
                        "bandwidthPercentage": int(value)
                    }
                    for key, value in new_queuing_profile_details['bandwidth_settings']['bandwidth_percentages'].items()
                ]
            }
        ]
    }
    param['clause'].append(bandwidth_clause)

if 'dscp' in new_queuing_profile_details['type']:
    dscp_clause = {
        "type": "DSCP_CUSTOMIZATION",
        "tcDscpSettings": [
            {
                "trafficClass": key.upper(),
                "dscp": value
            }
            for key, value in new_queuing_profile_details['dscp_settings'].items()
        ]
    }
    param['clause'].append(dscp_clause)

print(param)
