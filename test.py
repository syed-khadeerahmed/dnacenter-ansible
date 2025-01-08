# Define the variables
have_bandwidth_settings_100_GBPS = {'SIGNALING': '10', 'MULTIMEDIA_STREAMING': '5', 'VOIP_TELEPHONY': '20', 'BULK_DATA': '5', 'REAL_TIME_INTERACTIVE': '20', 'NETWORK_CONTROL': '3', 'BROADCAST_VIDEO': '2', 'TRANSACTIONAL_DATA': '4', 'BEST_EFFORT': '11', 'MULTIMEDIA_CONFERENCING': '10', 'OPS_ADMIN_MGMT': '5', 'SCAVENGER': '5'}
have_bandwidth_settings_100_MBPS = {'REAL_TIME_INTERACTIVE': '25', 'TRANSACTIONAL_DATA': '5', 'BULK_DATA': '5', 'SIGNALING': '10', 'VOIP_TELEPHONY': '5', 'SCAVENGER': '5', 'BEST_EFFORT': '10', 'BROADCAST_VIDEO': '2', 'MULTIMEDIA_STREAMING': '15', 'OPS_ADMIN_MGMT': '5', 'MULTIMEDIA_CONFERENCING': '10', 'NETWORK_CONTROL': '3'}
have_bandwidth_settings_10_GBPS = {'TRANSACTIONAL_DATA': '5', 'NETWORK_CONTROL': '3', 'OPS_ADMIN_MGMT': '4', 'MULTIMEDIA_CONFERENCING': '5', 'SCAVENGER': '5', 'BEST_EFFORT': '5', 'BROADCAST_VIDEO': '2', 'REAL_TIME_INTERACTIVE': '20', 'MULTIMEDIA_STREAMING': '5', 'VOIP_TELEPHONY': '25', 'BULK_DATA': '15', 'SIGNALING': '6'}
have_bandwidth_settings_10_MBPS = {'TRANSACTIONAL_DATA': '5', 'SIGNALING': '10', 'MULTIMEDIA_STREAMING': '11', 'SCAVENGER': '5', 'VOIP_TELEPHONY': '15', 'NETWORK_CONTROL': '3', 'BROADCAST_VIDEO': '2', 'REAL_TIME_INTERACTIVE': '19', 'BEST_EFFORT': '10', 'MULTIMEDIA_CONFERENCING': '10', 'BULK_DATA': '5', 'OPS_ADMIN_MGMT': '5'}
have_bandwidth_settings_1_GBPS = {'SCAVENGER': '5', 'OPS_ADMIN_MGMT': '5', 'BULK_DATA': '5', 'SIGNALING': '10', 'BEST_EFFORT': '10', 'TRANSACTIONAL_DATA': '5', 'MULTIMEDIA_CONFERENCING': '10', 'MULTIMEDIA_STREAMING': '11', 'REAL_TIME_INTERACTIVE': '19', 'VOIP_TELEPHONY': '15', 'BROADCAST_VIDEO': '2', 'NETWORK_CONTROL': '3'}
have_bandwidth_settings_1_MBPS = {'MULTIMEDIA_CONFERENCING': '10', 'SIGNALING': '10', 'TRANSACTIONAL_DATA': '5', 'REAL_TIME_INTERACTIVE': '19', 'MULTIMEDIA_STREAMING': '11', 'VOIP_TELEPHONY': '15', 'SCAVENGER': '5', 'NETWORK_CONTROL': '3', 'BULK_DATA': '5', 'OPS_ADMIN_MGMT': '5', 'BROADCAST_VIDEO': '2', 'BEST_EFFORT': '10'}

final_bandwidth_settings = {
    'HUNDRED_GBPS': {'SIGNALING': '10', 'MULTIMEDIA_STREAMING': '5', 'VOIP_TELEPHONY': '20', 'BULK_DATA': '5', 'REAL_TIME_INTERACTIVE': '20', 'NETWORK_CONTROL': '3', 'BROADCAST_VIDEO': '2', 'TRANSACTIONAL_DATA': '4', 'BEST_EFFORT': '11', 'MULTIMEDIA_CONFERENCING': '10', 'OPS_ADMIN_MGMT': '5', 'SCAVENGER': '5'},
    'HUNDRED_MBPS': {'REAL_TIME_INTERACTIVE': '25', 'TRANSACTIONAL_DATA': '5', 'BULK_DATA': '5', 'SIGNALING': '10', 'VOIP_TELEPHONY': '5', 'SCAVENGER': '5', 'BEST_EFFORT': '10', 'BROADCAST_VIDEO': '2', 'MULTIMEDIA_STREAMING': '15', 'OPS_ADMIN_MGMT': '5', 'MULTIMEDIA_CONFERENCING': '10', 'NETWORK_CONTROL': '3'},
    'TEN_GBPS': {'TRANSACTIONAL_DATA': '5', 'NETWORK_CONTROL': '3', 'OPS_ADMIN_MGMT': '4', 'MULTIMEDIA_CONFERENCING': '5', 'SCAVENGER': '5', 'BEST_EFFORT': '5', 'BROADCAST_VIDEO': '2', 'REAL_TIME_INTERACTIVE': '20', 'MULTIMEDIA_STREAMING': '5', 'VOIP_TELEPHONY': '25', 'BULK_DATA': '15', 'SIGNALING': '6'},
    'TEN_MBPS': {'TRANSACTIONAL_DATA': '5', 'SIGNALING': '10', 'MULTIMEDIA_STREAMING': '11', 'SCAVENGER': '5', 'VOIP_TELEPHONY': '15', 'NETWORK_CONTROL': '3', 'BROADCAST_VIDEO': '2', 'REAL_TIME_INTERACTIVE': '19', 'BEST_EFFORT': '10', 'MULTIMEDIA_CONFERENCING': '10', 'BULK_DATA': '5', 'OPS_ADMIN_MGMT': '5'},
    'ONE_GBPS': {'SCAVENGER': '5', 'OPS_ADMIN_MGMT': '5', 'BULK_DATA': '5', 'SIGNALING': '10', 'BEST_EFFORT': '10', 'TRANSACTIONAL_DATA': '5', 'MULTIMEDIA_CONFERENCING': '10', 'MULTIMEDIA_STREAMING': '11', 'REAL_TIME_INTERACTIVE': '19', 'VOIP_TELEPHONY': '15', 'BROADCAST_VIDEO': '2', 'NETWORK_CONTROL': '3'},
    'ONE_MBPS': {'MULTIMEDIA_CONFERENCING': '10', 'SIGNALING': '10', 'TRANSACTIONAL_DATA': '5', 'REAL_TIME_INTERACTIVE': '19', 'MULTIMEDIA_STREAMING': '11', 'VOIP_TELEPHONY': '15', 'SCAVENGER': '5', 'NETWORK_CONTROL': '3', 'BULK_DATA': '5', 'OPS_ADMIN_MGMT': '5', 'BROADCAST_VIDEO': '2', 'BEST_EFFORT': '10'}
}

bandwidth_update_required = False

for speed, final_bandwidth in final_bandwidth_settings.items():
    if speed == 'HUNDRED_GBPS':
        have_bandwidth = have_bandwidth_settings_100_GBPS
    elif speed == 'HUNDRED_MBPS':
        have_bandwidth = have_bandwidth_settings_100_MBPS
    elif speed == 'TEN_GBPS':
        have_bandwidth = have_bandwidth_settings_10_GBPS
    elif speed == 'TEN_MBPS':
        have_bandwidth = have_bandwidth_settings_10_MBPS
    elif speed == 'ONE_GBPS':
        have_bandwidth = have_bandwidth_settings_1_GBPS
    elif speed == 'ONE_MBPS':
        have_bandwidth = have_bandwidth_settings_1_MBPS
    
    for traffic_class, final_value in final_bandwidth.items():
        have_value = have_bandwidth.get(traffic_class, None)
        if have_value != final_value:
            bandwidth_update_required = True 

print("\nUpdate required:", bandwidth_update_required)