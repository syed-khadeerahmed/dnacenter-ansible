required_details = {'profile_name': 'sample_q_p3', 'profile_description': 'sample desc', 'bandwidth_settings': {'is_common_between_all_interface_speeds': False, 'interface_speed_settings': [{'interface_speed': 'HUNDRED_GBPS', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '10', 'voip_telephony': '20', 'multimedia_streaming': '5', 'real_time_interactive': '20', 'multimedia_conferencing': '10', 'signaling': '10', 'scavenger': '5', 'ops_admin_mgmt': '5', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '5'}}, {'interface_speed': 'TEN_GBPS', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '5', 'voip_telephony': '25', 'multimedia_streaming': '5', 'real_time_interactive': '20', 'multimedia_conferencing': '5', 'signaling': '6', 'scavenger': '5', 'ops_admin_mgmt': '4', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '15'}}, {'interface_speed': 'HUNDRED_MBPS', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '10', 'voip_telephony': '5', 'multimedia_streaming': '15', 'real_time_interactive': '25', 'multimedia_conferencing': '10', 'signaling': '10', 'scavenger': '5', 'ops_admin_mgmt': '5', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '5'}}, {'interface_speed': 'TEN_MBPS, ONE_MBPS, ONE_GBPS', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '10', 'voip_telephony': '15', 'multimedia_streaming': '10', 'real_time_interactive': '20', 'multimedia_conferencing': '10', 'signaling': '10', 'scavenger': '5', 'ops_admin_mgmt': '5', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '5'}}]}, 'dscp_settings': {'multimedia_conferencing': '20', 'ops_admin_mgmt': '23', 'transactional_data': '28', 'voip_telephony': '45', 'multimedia_streaming': '27', 'broadcast_video': '46', 'network_control': '48', 'best_effort': '0', 'signaling': '6', 'bulk_data': '10', 'scavenger': '2', 'real_time_interactive': '34'}}

current_profiles = [
  {
    'id': '6cacacae-af8d-442c-b92a-12cfc950b69a',
    'instanceId': 15822221,
    'instanceCreatedOn': 1735818840713,
    'instanceUpdatedOn': 1735818840713,
    'instanceVersion': 0,
    'createTime': 1735818840704,
    'deployed': False,
    'description': 'sample desc',
    'isSeeded': False,
    'isStale': False,
    'lastUpdateTime': 1735818840704,
    'name': 'sample_q_p3',
    'namespace': '6cacacae-af8d-442c-b92a-12cfc950b69a',
    'provisioningState': 'DEFINED',
    'qualifier': 'application',
    'resourceVersion': 0,
    'targetIdList': [
      
    ],
    'type': 'contract',
    'cfsChangeInfo': [
      
    ],
    'customProvisions': [
      
    ],
    'externalIntentSourceInfos': [
      
    ],
    'genId': 0,
    'internal': False,
    'isDeleted': False,
    'iseReserved': False,
    'pushed': False,
    'clause': [
      {
        'id': 'ed2a88e6-db33-4e48-8049-2b550191c89a',
        'instanceId': 131679633,
        'instanceCreatedOn': 1735818840713,
        'instanceUpdatedOn': 1735818840713,
        'instanceVersion': 0,
        'priority': 1,
        'isCommonBetweenAllInterfaceSpeeds': False,
        'interfaceSpeedBandwidthClauses': [
          {
            'id': '3d1a4381-e068-44f9-9492-2096ce1cd09f',
            'instanceId': 131681583,
            'instanceCreatedOn': 1735818840713,
            'instanceUpdatedOn': 1735818840713,
            'instanceVersion': 0,
            'interfaceSpeed': 'HUNDRED_MBPS',
            'tcBandwidthSettings': [
              {
                'id': '691b17fd-23e3-4318-8f4d-d0e498e12659',
                'instanceId': 131682953,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'SIGNALING',
                'displayName': '0'
              },
              {
                'id': '593c6af5-bb6a-4060-b8f0-7d25cfea6a38',
                'instanceId': 131682952,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'BEST_EFFORT',
                'displayName': '0'
              },
              {
                'id': '50bb67c3-b054-4fb4-9dff-8122a66a97cf',
                'instanceId': 131682955,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'SCAVENGER',
                'displayName': '0'
              },
              {
                'id': 'cfbb3f86-4ae3-46e4-8304-28971708d7aa',
                'instanceId': 131682954,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'OPS_ADMIN_MGMT',
                'displayName': '0'
              },
              {
                'id': 'e7a0ea31-cfe0-42d5-b784-1886ec41dcf6',
                'instanceId': 131682957,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 3,
                'trafficClass': 'NETWORK_CONTROL',
                'displayName': '0'
              },
              {
                'id': '4a427add-f6c0-449f-84a5-f066f16c740a',
                'instanceId': 131682956,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'TRANSACTIONAL_DATA',
                'displayName': '0'
              },
              {
                'id': 'eae1cd4c-a137-48c6-af6e-1ededff5ea4b',
                'instanceId': 131682958,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'BULK_DATA',
                'displayName': '0'
              },
              {
                'id': 'd5525431-3db7-4b9b-b78d-61304cfb7232',
                'instanceId': 131682947,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 25,
                'trafficClass': 'REAL_TIME_INTERACTIVE',
                'displayName': '0'
              },
              {
                'id': '8bf568e5-a5b0-4eb9-8249-76b11f4f38be',
                'instanceId': 131682949,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'VOIP_TELEPHONY',
                'displayName': '0'
              },
              {
                'id': '9b90fdda-b900-420a-9189-80b4482ab26a',
                'instanceId': 131682948,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'MULTIMEDIA_CONFERENCING',
                'displayName': '0'
              },
              {
                'id': 'e13a721e-cc96-4079-b18e-65ea7534246a',
                'instanceId': 131682951,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 15,
                'trafficClass': 'MULTIMEDIA_STREAMING',
                'displayName': '0'
              },
              {
                'id': '3a8d74fd-86fd-49fe-8f3c-c1d2550703c2',
                'instanceId': 131682950,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 2,
                'trafficClass': 'BROADCAST_VIDEO',
                'displayName': '0'
              }
            ],
            'displayName': '0'
          },
          {
            'id': '02302bce-71bf-43b2-a8b3-98b5dc521c66',
            'instanceId': 131681582,
            'instanceCreatedOn': 1735818840713,
            'instanceUpdatedOn': 1735818840713,
            'instanceVersion': 0,
            'interfaceSpeed': 'HUNDRED_GBPS',
            'tcBandwidthSettings': [
              {
                'id': 'ff818f11-718a-4c55-a2c6-34b6c2fdb503',
                'instanceId': 131682937,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'MULTIMEDIA_CONFERENCING',
                'displayName': '0'
              },
              {
                'id': '41870ba8-6620-46b9-8168-cbf9c198afa1',
                'instanceId': 131682936,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 2,
                'trafficClass': 'BROADCAST_VIDEO',
                'displayName': '0'
              },
              {
                'id': '3d42f9ac-1634-46b5-832c-d15b1b05789e',
                'instanceId': 131682939,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 3,
                'trafficClass': 'NETWORK_CONTROL',
                'displayName': '0'
              },
              {
                'id': '4c31b601-9788-446d-bb3a-b39f17b2bff2',
                'instanceId': 131682938,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'SCAVENGER',
                'displayName': '0'
              },
              {
                'id': '076b6e14-a63c-47b7-8f43-1f730adcb6b3',
                'instanceId': 131682941,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'BULK_DATA',
                'displayName': '0'
              },
              {
                'id': '63753c19-f212-4496-bec3-1090737e6f71',
                'instanceId': 131682940,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'BEST_EFFORT',
                'displayName': '0'
              },
              {
                'id': '80e1c4d0-46d5-4f50-ab41-d8566a087d20',
                'instanceId': 131682943,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 20,
                'trafficClass': 'REAL_TIME_INTERACTIVE',
                'displayName': '0'
              },
              {
                'id': '93c850f8-afcd-4aaa-b6f9-b073295528a3',
                'instanceId': 131682942,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'TRANSACTIONAL_DATA',
                'displayName': '0'
              },
              {
                'id': '15abf83d-e3ff-4522-9ae2-0ffc6a4d4e39',
                'instanceId': 131682945,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'MULTIMEDIA_STREAMING',
                'displayName': '0'
              },
              {
                'id': '251a6505-1ce6-47e4-a28c-785c573b8755',
                'instanceId': 131682944,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'SIGNALING',
                'displayName': '0'
              },
              {
                'id': '1e652be7-3a98-42a0-8d15-e53adb44222a',
                'instanceId': 131682946,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 20,
                'trafficClass': 'VOIP_TELEPHONY',
                'displayName': '0'
              },
              {
                'id': 'd46e2eff-913b-44da-9bd0-881daad990c4',
                'instanceId': 131682935,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'OPS_ADMIN_MGMT',
                'displayName': '0'
              }
            ],
            'displayName': '0'
          },
          {
            'id': '0f6f302a-1795-4603-a29d-6f277af5e016',
            'instanceId': 131681585,
            'instanceCreatedOn': 1735818840713,
            'instanceUpdatedOn': 1735818840713,
            'instanceVersion': 0,
            'interfaceSpeed': 'ONE_MBPS',
            'tcBandwidthSettings': [
              {
                'id': '279fcb3d-6b30-4005-9173-a8500bcbc462',
                'instanceId': 131682971,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'BULK_DATA',
                'displayName': '0'
              },
              {
                'id': '8b9ae3b2-dc65-4794-8ad0-786e3550af6b',
                'instanceId': 131682973,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'MULTIMEDIA_CONFERENCING',
                'displayName': '0'
              },
              {
                'id': '80be20e0-6c34-4bd0-abf3-50f637633804',
                'instanceId': 131682972,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 20,
                'trafficClass': 'REAL_TIME_INTERACTIVE',
                'displayName': '0'
              },
              {
                'id': 'e78da784-1721-45a4-9272-743ba2ed406b',
                'instanceId': 131682975,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 3,
                'trafficClass': 'NETWORK_CONTROL',
                'displayName': '0'
              },
              {
                'id': '96bf9e44-6bfb-441d-867f-ec7ded1cee7a',
                'instanceId': 131682974,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'SCAVENGER',
                'displayName': '0'
              },
              {
                'id': '2ec938d7-2964-4db4-b874-5fa607cb4ed2',
                'instanceId': 131682977,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'BEST_EFFORT',
                'displayName': '0'
              },
              {
                'id': 'f2d4bf50-3346-4d5c-bb97-121160ae1870',
                'instanceId': 131682976,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'MULTIMEDIA_STREAMING',
                'displayName': '0'
              },
              {
                'id': '10fd4e03-793d-4ae5-84ad-718df9e98ffd',
                'instanceId': 131682979,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'OPS_ADMIN_MGMT',
                'displayName': '0'
              },
              {
                'id': '998561d0-af36-4f3c-9f4d-c559cc6ebf89',
                'instanceId': 131682978,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 2,
                'trafficClass': 'BROADCAST_VIDEO',
                'displayName': '0'
              },
              {
                'id': 'b423a6e0-0211-4899-acba-878cf413bf29',
                'instanceId': 131682981,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 15,
                'trafficClass': 'VOIP_TELEPHONY',
                'displayName': '0'
              },
              {
                'id': '1065992d-551e-4cf2-8035-c17d3c0d0510',
                'instanceId': 131682980,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'SIGNALING',
                'displayName': '0'
              },
              {
                'id': 'cb417249-6218-4859-885b-cbbf5e9b8afc',
                'instanceId': 131682982,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'TRANSACTIONAL_DATA',
                'displayName': '0'
              }
            ],
            'displayName': '0'
          },
          {
            'id': '7a6d2ab1-7124-4ddb-a690-68d312e245ae',
            'instanceId': 131681584,
            'instanceCreatedOn': 1735818840713,
            'instanceUpdatedOn': 1735818840713,
            'instanceVersion': 0,
            'interfaceSpeed': 'TEN_MBPS',
            'tcBandwidthSettings': [
              {
                'id': '0f372fc7-8a34-4a8e-90e7-fe4a4cf71531',
                'instanceId': 131682969,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'SIGNALING',
                'displayName': '0'
              },
              {
                'id': 'cd37f7be-8383-4eb0-8306-b840a9af6f4b',
                'instanceId': 131682968,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 2,
                'trafficClass': 'BROADCAST_VIDEO',
                'displayName': '0'
              },
              {
                'id': 'd2b498ad-1f35-460e-9360-b1557611a1a0',
                'instanceId': 131682970,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'SCAVENGER',
                'displayName': '0'
              },
              {
                'id': '9a581910-260c-4a9a-bc07-d7316bd54a1d',
                'instanceId': 131682959,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'MULTIMEDIA_STREAMING',
                'displayName': '0'
              },
              {
                'id': 'b3a1d491-dda9-49d5-bc1b-089b33d4563b',
                'instanceId': 131682961,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'BULK_DATA',
                'displayName': '0'
              },
              {
                'id': '4071877b-c03f-4049-8396-51e9889f9229',
                'instanceId': 131682960,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'BEST_EFFORT',
                'displayName': '0'
              },
              {
                'id': 'c3c401d5-38d3-4893-a79b-ee1ba8331cdc',
                'instanceId': 131682963,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 20,
                'trafficClass': 'REAL_TIME_INTERACTIVE',
                'displayName': '0'
              },
              {
                'id': 'bd154d24-3978-4892-9c91-3ac330d3a829',
                'instanceId': 131682962,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'OPS_ADMIN_MGMT',
                'displayName': '0'
              },
              {
                'id': '7e9187b4-4afa-464d-ad51-c13ded2ef399',
                'instanceId': 131682965,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 3,
                'trafficClass': 'NETWORK_CONTROL',
                'displayName': '0'
              },
              {
                'id': 'af3b0530-f169-4c1c-8cbd-381956326f3a',
                'instanceId': 131682964,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'MULTIMEDIA_CONFERENCING',
                'displayName': '0'
              },
              {
                'id': '3dd77eb8-c335-4353-88c4-44113be7b7b8',
                'instanceId': 131682967,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 15,
                'trafficClass': 'VOIP_TELEPHONY',
                'displayName': '0'
              },
              {
                'id': '51c8570d-4515-41d9-b994-176f47ca68a2',
                'instanceId': 131682966,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'TRANSACTIONAL_DATA',
                'displayName': '0'
              }
            ],
            'displayName': '0'
          },
          {
            'id': '2069dc2d-a871-4db2-9ace-dc042e807309',
            'instanceId': 131681587,
            'instanceCreatedOn': 1735818840713,
            'instanceUpdatedOn': 1735818840713,
            'instanceVersion': 0,
            'interfaceSpeed': 'TEN_GBPS',
            'tcBandwidthSettings': [
              {
                'id': 'e92421a9-58f9-4221-ab10-0e757fbcaa47',
                'instanceId': 131683001,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'BEST_EFFORT',
                'displayName': '0'
              },
              {
                'id': '737928bf-548f-492e-818b-5924a4bc2153',
                'instanceId': 131683000,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 20,
                'trafficClass': 'REAL_TIME_INTERACTIVE',
                'displayName': '0'
              },
              {
                'id': 'ecd2dceb-ab83-4313-a641-c5c83cb20228',
                'instanceId': 131683003,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'MULTIMEDIA_STREAMING',
                'displayName': '0'
              },
              {
                'id': '611becba-dd76-41f4-9b86-2d98fc481d82',
                'instanceId': 131683002,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'TRANSACTIONAL_DATA',
                'displayName': '0'
              },
              {
                'id': '4943f59a-102b-45e7-9f2f-e20c47bed55f',
                'instanceId': 131683005,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 3,
                'trafficClass': 'NETWORK_CONTROL',
                'displayName': '0'
              },
              {
                'id': '09aebff0-dab3-4ae9-993d-634480e6fbf1',
                'instanceId': 131683004,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 4,
                'trafficClass': 'OPS_ADMIN_MGMT',
                'displayName': '0'
              },
              {
                'id': 'c2395b56-bc59-4017-9769-4e94d5c8fac9',
                'instanceId': 131683006,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 2,
                'trafficClass': 'BROADCAST_VIDEO',
                'displayName': '0'
              },
              {
                'id': 'c9c0fc0d-1c55-4efc-918e-96ba2a4d4f23',
                'instanceId': 131682995,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 15,
                'trafficClass': 'BULK_DATA',
                'displayName': '0'
              },
              {
                'id': '678a9301-48f1-40f7-ba79-9558162842a9',
                'instanceId': 131682997,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 6,
                'trafficClass': 'SIGNALING',
                'displayName': '0'
              },
              {
                'id': '8d8358dc-130b-4b2c-99fd-629bbcf9a57a',
                'instanceId': 131682996,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'MULTIMEDIA_CONFERENCING',
                'displayName': '0'
              },
              {
                'id': '40e05606-3865-4a80-ba9e-19f8cc9736b3',
                'instanceId': 131682999,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 25,
                'trafficClass': 'VOIP_TELEPHONY',
                'displayName': '0'
              },
              {
                'id': '040bfcb3-ac41-4275-8030-bbf644072c2d',
                'instanceId': 131682998,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'SCAVENGER',
                'displayName': '0'
              }
            ],
            'displayName': '0'
          },
          {
            'id': '5ba4a3b1-fd57-4729-99b1-d568c020c09c',
            'instanceId': 131681586,
            'instanceCreatedOn': 1735818840713,
            'instanceUpdatedOn': 1735818840713,
            'instanceVersion': 0,
            'interfaceSpeed': 'ONE_GBPS',
            'tcBandwidthSettings': [
              {
                'id': '2b867d6e-86da-44f2-ae13-ecac82b39e9b',
                'instanceId': 131682985,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'MULTIMEDIA_STREAMING',
                'displayName': '0'
              },
              {
                'id': '2f92b6b1-18ad-40a7-977c-45840cd0b990',
                'instanceId': 131682984,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'SCAVENGER',
                'displayName': '0'
              },
              {
                'id': '8e7faec6-c934-4b5c-ba56-d87d085237d7',
                'instanceId': 131682987,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'SIGNALING',
                'displayName': '0'
              },
              {
                'id': 'be4a8ff4-eb3b-4eba-92c2-90043dfdc5ce',
                'instanceId': 131682986,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 3,
                'trafficClass': 'NETWORK_CONTROL',
                'displayName': '0'
              },
              {
                'id': '336c840d-8da9-49f3-a8a1-46ccd00eaaab',
                'instanceId': 131682989,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'MULTIMEDIA_CONFERENCING',
                'displayName': '0'
              },
              {
                'id': '08b75b89-a364-47cc-a071-5bb395a586b0',
                'instanceId': 131682988,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'BULK_DATA',
                'displayName': '0'
              },
              {
                'id': 'c71d0ebe-25e3-4274-aeb9-1678f78ad776',
                'instanceId': 131682991,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 2,
                'trafficClass': 'BROADCAST_VIDEO',
                'displayName': '0'
              },
              {
                'id': '7b0e0770-1469-4840-a0eb-4f1c953540a9',
                'instanceId': 131682990,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'BEST_EFFORT',
                'displayName': '0'
              },
              {
                'id': '79b1ce57-ee7b-4b74-9f83-6480dafef2ee',
                'instanceId': 131682993,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'TRANSACTIONAL_DATA',
                'displayName': '0'
              },
              {
                'id': 'ea6caf7e-76ba-4a8d-b210-b4b2a37b5223',
                'instanceId': 131682992,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'OPS_ADMIN_MGMT',
                'displayName': '0'
              },
              {
                'id': '2ab14db2-98d5-48ab-8b55-891d74edb6ae',
                'instanceId': 131682994,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 15,
                'trafficClass': 'VOIP_TELEPHONY',
                'displayName': '0'
              },
              {
                'id': '7ae34b34-05db-43c8-9fc8-db4f40009458',
                'instanceId': 131682983,
                'instanceCreatedOn': 1735818840713,
                'instanceUpdatedOn': 1735818840713,
                'instanceVersion': 0,
                'bandwidthPercentage': 20,
                'trafficClass': 'REAL_TIME_INTERACTIVE',
                'displayName': '0'
              }
            ],
            'displayName': '0'
          }
        ],
        'displayName': '0'
      },
      {
        'id': 'f9ca422c-562b-450b-b74e-f79d91bfbbb3',
        'instanceId': 131679632,
        'instanceCreatedOn': 1735818840713,
        'instanceUpdatedOn': 1735818840713,
        'instanceVersion': 0,
        'priority': 1,
        'type': 'DSCP_CUSTOMIZATION',
        'tcDscpSettings': [
          {
            'id': 'fb470261-8cf6-41ee-99ce-8d0f3d15d235',
            'instanceId': 131680681,
            'instanceCreatedOn': 1735818840713,
            'instanceUpdatedOn': 1735818840713,
            'instanceVersion': 0,
            'dscp': '10',
            'trafficClass': 'BULK_DATA',
            'displayName': '0'
          },
          {
            'id': 'f5f8dbff-37bf-450c-95e8-a8efe287e003',
            'instanceId': 131680683,
            'instanceCreatedOn': 1735818840713,
            'instanceUpdatedOn': 1735818840713,
            'instanceVersion': 0,
            'dscp': '27',
            'trafficClass': 'MULTIMEDIA_STREAMING',
            'displayName': '0'
          },
          {
            'id': 'fad5e084-d5bd-4172-a9ec-f581589e27cf',
            'instanceId': 131680682,
            'instanceCreatedOn': 1735818840713,
            'instanceUpdatedOn': 1735818840713,
            'instanceVersion': 0,
            'dscp': '7',
            'trafficClass': 'SIGNALING',
            'displayName': '0'
          },
          {
            'id': 'df6cded3-893f-45cb-93ac-8bff17c03b00',
            'instanceId': 131680685,
            'instanceCreatedOn': 1735818840713,
            'instanceUpdatedOn': 1735818840713,
            'instanceVersion': 0,
            'dscp': '2',
            'trafficClass': 'SCAVENGER',
            'displayName': '0'
          },
          {
            'id': '129c2e1b-440e-4e9b-bc8f-febdd03caa0f',
            'instanceId': 131680684,
            'instanceCreatedOn': 1735818840713,
            'instanceUpdatedOn': 1735818840713,
            'instanceVersion': 0,
            'dscp': '46',
            'trafficClass': 'BROADCAST_VIDEO',
            'displayName': '0'
          },
          {
            'id': 'b69ae6ce-e0c6-492e-aafa-5a5866b4c23c',
            'instanceId': 131680687,
            'instanceCreatedOn': 1735818840713,
            'instanceUpdatedOn': 1735818840713,
            'instanceVersion': 0,
            'dscp': '23',
            'trafficClass': 'OPS_ADMIN_MGMT',
            'displayName': '0'
          },
          {
            'id': 'ab59d69e-fadf-4edf-ab9e-6148b1eb14ea',
            'instanceId': 131680686,
            'instanceCreatedOn': 1735818840713,
            'instanceUpdatedOn': 1735818840713,
            'instanceVersion': 0,
            'dscp': '48',
            'trafficClass': 'NETWORK_CONTROL',
            'displayName': '0'
          },
          {
            'id': '3f29998c-7bcd-4f3e-9fa6-46663c959c0f',
            'instanceId': 131680689,
            'instanceCreatedOn': 1735818840713,
            'instanceUpdatedOn': 1735818840713,
            'instanceVersion': 0,
            'dscp': '0',
            'trafficClass': 'BEST_EFFORT',
            'displayName': '0'
          },
          {
            'id': '091aa407-c287-4171-82e8-2a54798c83a1',
            'instanceId': 131680688,
            'instanceCreatedOn': 1735818840713,
            'instanceUpdatedOn': 1735818840713,
            'instanceVersion': 0,
            'dscp': '28',
            'trafficClass': 'TRANSACTIONAL_DATA',
            'displayName': '0'
          },
          {
            'id': '7d542fab-7a4c-4776-8ef7-65de55b89cdf',
            'instanceId': 131680691,
            'instanceCreatedOn': 1735818840713,
            'instanceUpdatedOn': 1735818840713,
            'instanceVersion': 0,
            'dscp': '34',
            'trafficClass': 'REAL_TIME_INTERACTIVE',
            'displayName': '0'
          },
          {
            'id': '0b1153b8-c55a-4e28-b7b8-0fa92175fb60',
            'instanceId': 131680690,
            'instanceCreatedOn': 1735818840713,
            'instanceUpdatedOn': 1735818840713,
            'instanceVersion': 0,
            'dscp': '45',
            'trafficClass': 'VOIP_TELEPHONY',
            'displayName': '0'
          },
          {
            'id': '7e2fb205-5abd-455e-b93b-4282a8a89d19',
            'instanceId': 131680692,
            'instanceCreatedOn': 1735818840713,
            'instanceUpdatedOn': 1735818840713,
            'instanceVersion': 0,
            'dscp': '20',
            'trafficClass': 'MULTIMEDIA_CONFERENCING',
            'displayName': '0'
          }
        ],
        'displayName': '0'
      }
    ],
    'contractClassifier': [
      
    ],
    'displayName': '0'
  }
]

# Check if the interface speed matches and assign the settings
want_bandwidth_settings_100_GBPS = None
want_bandwidth_settings_10_GBPS = None
want_bandwidth_settings_1_GBPS = None
want_bandwidth_settings_100_MBPS = None
want_bandwidth_settings_10_MBPS = None
want_bandwidth_settings_1_MBPS = None

for setting in required_details['bandwidth_settings']['interface_speed_settings']:
    if "HUNDRED_GBPS" in setting['interface_speed']:
        want_bandwidth_settings_100_GBPS = setting.get("bandwidth_percentages")
    if "HUNDRED_MBPS" in setting['interface_speed']:
        want_bandwidth_settings_100_MBPS = setting.get("bandwidth_percentages")
    if "TEN_GBPS" in setting['interface_speed']:
        want_bandwidth_settings_10_GBPS = setting.get("bandwidth_percentages")
    if "TEN_MBPS" in setting['interface_speed']:
        want_bandwidth_settings_10_MBPS = setting.get("bandwidth_percentages")
    if "ONE_GBPS" in setting['interface_speed']:
        want_bandwidth_settings_1_GBPS = setting.get("bandwidth_percentages")
    if "ONE_MBPS" in setting['interface_speed']:
        want_bandwidth_settings_1_MBPS = setting.get("bandwidth_percentages")

# Print the result
print("want_bandwidth_settings_100_GBPS:", want_bandwidth_settings_100_GBPS)
print("want_bandwidth_settings_10_GBPS:", want_bandwidth_settings_10_GBPS)
print("want_bandwidth_settings_1_GBPS:", want_bandwidth_settings_1_GBPS)
print("want_bandwidth_settings_100_MBPS:", want_bandwidth_settings_100_MBPS)
print("want_bandwidth_settings_10_MBPS:", want_bandwidth_settings_10_MBPS)
print("want_bandwidth_settings_1_MBPS:", want_bandwidth_settings_1_MBPS)


have_bandwidth_settings_100_GBPS, have_bandwidth_settings_100_MBPS, have_bandwidth_settings_10_GBPS = {}, {}, {}
have_bandwidth_settings_10_MBPS, have_bandwidth_settings_1_GBPS, have_bandwidth_settings_1_MBPS = {}, {}, {}

instance_id_bandwidth_settings_100_GBPS, instance_id_bandwidth_settings_100_MBPS, instance_id_bandwidth_settings_10_GBPS = {}, {}, {}
instance_id_bandwidth_settings_10_MBPS, instance_id_bandwidth_settings_1_GBPS, instance_id_bandwidth_settings_1_MBPS = {}, {}, {}


for profile in current_profiles:
    for clause in profile.get('clause', []):
        for interface_speed_bandwidth_clause in clause.get('interfaceSpeedBandwidthClauses', []):
            if interface_speed_bandwidth_clause.get("interfaceSpeed") == "HUNDRED_GBPS":
                for setting in interface_speed_bandwidth_clause['tcBandwidthSettings']:
                    traffic_class = setting['trafficClass'].upper().replace(' ', '_')  # Normalize to uppercase
                    bandwidth_percentage = str(setting['bandwidthPercentage'])  # Convert to string
                    instance_id = (setting['instanceId']) 
                    have_bandwidth_settings_100_GBPS[traffic_class] = bandwidth_percentage
                    instance_id_bandwidth_settings_100_GBPS[traffic_class] = instance_id

            if interface_speed_bandwidth_clause.get("interfaceSpeed") == "HUNDRED_MBPS":
                for setting in interface_speed_bandwidth_clause['tcBandwidthSettings']:
                    traffic_class = setting['trafficClass'].upper().replace(' ', '_')  # Normalize to uppercase
                    bandwidth_percentage = str(setting['bandwidthPercentage'])  # Convert to string
                    instance_id = (setting['instanceId']) 
                    have_bandwidth_settings_100_MBPS[traffic_class] = bandwidth_percentage
                    instance_id_bandwidth_settings_100_MBPS[traffic_class] = instance_id

            if interface_speed_bandwidth_clause.get("interfaceSpeed") == "TEN_GBPS":
                for setting in interface_speed_bandwidth_clause['tcBandwidthSettings']:
                    traffic_class = setting['trafficClass'].upper().replace(' ', '_')  # Normalize to uppercase
                    bandwidth_percentage = str(setting['bandwidthPercentage'])  # Convert to string
                    instance_id = (setting['instanceId']) 
                    have_bandwidth_settings_10_GBPS[traffic_class] = bandwidth_percentage
                    instance_id_bandwidth_settings_10_GBPS[traffic_class] = instance_id

            if interface_speed_bandwidth_clause.get("interfaceSpeed") == "TEN_MBPS":
                for setting in interface_speed_bandwidth_clause['tcBandwidthSettings']:
                    traffic_class = setting['trafficClass'].upper().replace(' ', '_')  # Normalize to uppercase
                    bandwidth_percentage = str(setting['bandwidthPercentage'])  # Convert to string
                    instance_id = (setting['instanceId']) 
                    have_bandwidth_settings_10_MBPS[traffic_class] = bandwidth_percentage
                    instance_id_bandwidth_settings_10_MBPS[traffic_class] = instance_id

            if interface_speed_bandwidth_clause.get("interfaceSpeed") == "ONE_GBPS":
                for setting in interface_speed_bandwidth_clause['tcBandwidthSettings']:
                    traffic_class = setting['trafficClass'].upper().replace(' ', '_')  # Normalize to uppercase
                    bandwidth_percentage = str(setting['bandwidthPercentage'])  # Convert to string
                    instance_id = (setting['instanceId']) 
                    have_bandwidth_settings_1_GBPS[traffic_class] = bandwidth_percentage
                    instance_id_bandwidth_settings_1_GBPS[traffic_class] = instance_id
            if interface_speed_bandwidth_clause.get("interfaceSpeed") == "ONE_MBPS":
                for setting in interface_speed_bandwidth_clause['tcBandwidthSettings']:
                    traffic_class = setting['trafficClass'].upper().replace(' ', '_')  # Normalize to uppercase
                    bandwidth_percentage = str(setting['bandwidthPercentage'])  # Convert to string
                    instance_id = (setting['instanceId']) 
                    have_bandwidth_settings_1_MBPS[traffic_class] = bandwidth_percentage
                    instance_id_bandwidth_settings_1_MBPS[traffic_class] = instance_id

print("--------------------------------------------------------------------------------")
print("instance_id_bandwidth_settings_100_GBPS:", instance_id_bandwidth_settings_100_GBPS)
print("instance_id_bandwidth_settings_100_MBPS:", instance_id_bandwidth_settings_100_MBPS)
print("instance_id_bandwidth_settings_10_GBPS:", instance_id_bandwidth_settings_10_GBPS)
print("instance_id_bandwidth_settings_10_MBPS:", instance_id_bandwidth_settings_10_MBPS)
print("instance_id_bandwidth_settings_1_GBPS:", instance_id_bandwidth_settings_1_GBPS)
print("instance_id_bandwidth_settings_1_MBPS:", instance_id_bandwidth_settings_1_MBPS)
print("--------------------------------------------------------------------------------")
# Now interfaceSpeedBandwidthClauses contains the extracted list
print("have_bandwidth_settings_100_GBPS:", have_bandwidth_settings_100_GBPS)
print("have_bandwidth_settings_100_MBPS:", have_bandwidth_settings_100_MBPS)
print("have_bandwidth_settings_10_GBPS:", have_bandwidth_settings_10_GBPS)
print("have_bandwidth_settings_10_MBPS:", have_bandwidth_settings_10_MBPS)
print("have_bandwidth_settings_1_GBPS:", have_bandwidth_settings_1_GBPS)
print("have_bandwidth_settings_1_MBPS:", have_bandwidth_settings_1_MBPS)

# Normalizing traffic classes to uppercase for comparison
final_want_bandwidth_settings_100_GBPS = {}
final_want_bandwidth_settings_100_MBPS = {}
final_want_bandwidth_settings_10_GBPS = {}
final_want_bandwidth_settings_10_MBPS = {}
final_want_bandwidth_settings_1_GBPS = {}
final_want_bandwidth_settings_1_MBPS = {}

for speed, want_bandwidth_settings, have_bandwidth_settings, final_want_bandwidth_settings in [
    ("100_GBPS", want_bandwidth_settings_100_GBPS, have_bandwidth_settings_100_GBPS, final_want_bandwidth_settings_100_GBPS),
    ("100_MBPS", want_bandwidth_settings_100_MBPS, have_bandwidth_settings_100_MBPS, final_want_bandwidth_settings_100_MBPS),
    ("10_GBPS", want_bandwidth_settings_10_GBPS, have_bandwidth_settings_10_GBPS, final_want_bandwidth_settings_10_GBPS),
    ("10_MBPS", want_bandwidth_settings_10_MBPS, have_bandwidth_settings_10_MBPS, final_want_bandwidth_settings_10_MBPS),
    ("1_GBPS", want_bandwidth_settings_1_GBPS, have_bandwidth_settings_1_GBPS, final_want_bandwidth_settings_1_GBPS),
    ("1_MBPS", want_bandwidth_settings_1_MBPS, have_bandwidth_settings_1_MBPS, final_want_bandwidth_settings_1_MBPS)
]:
    # Compare and merge `want_bandwidth_settings` and `have_bandwidth_settings`
    for key, value in want_bandwidth_settings.items():
        normalized_key = key.upper().replace(' ', '_')  # Normalize key to uppercase with underscores
        if normalized_key in have_bandwidth_settings:
            if have_bandwidth_settings[normalized_key] != value:
                final_want_bandwidth_settings[normalized_key] = value
            else:
                final_want_bandwidth_settings[normalized_key] = have_bandwidth_settings[normalized_key]
        else:
            final_want_bandwidth_settings[normalized_key] = value

    # Now check for entries in `have_bandwidth_settings` not in `want_bandwidth_settings`
    for key, value in have_bandwidth_settings.items():
        if key not in final_want_bandwidth_settings:
            final_want_bandwidth_settings[key] = value
print("--------------------------------------------------------------------------------")
# Print the final dictionaries for all speeds
print("final_want_bandwidth_settings_100_GBPS:", final_want_bandwidth_settings_100_GBPS)
print("final_want_bandwidth_settings_100_MBPS:", final_want_bandwidth_settings_100_MBPS)
print("final_want_bandwidth_settings_10_GBPS:", final_want_bandwidth_settings_10_GBPS)
print("final_want_bandwidth_settings_10_MBPS:", final_want_bandwidth_settings_10_MBPS)
print("final_want_bandwidth_settings_1_GBPS:", final_want_bandwidth_settings_1_GBPS)
print("final_want_bandwidth_settings_1_MBPS:", final_want_bandwidth_settings_1_MBPS)

instance_id_bandwidth_settings = {
    "HUNDRED_GBPS": {key: instance_id_bandwidth_settings_100_GBPS.get(key, None) for key in final_want_bandwidth_settings_100_GBPS},
    "HUNDRED_MBPS": {key: instance_id_bandwidth_settings_100_MBPS.get(key, None) for key in final_want_bandwidth_settings_100_MBPS},
    "TEN_GBPS": {key: instance_id_bandwidth_settings_10_GBPS.get(key, None) for key in final_want_bandwidth_settings_10_GBPS},
    "TEN_MBPS": {key: instance_id_bandwidth_settings_10_MBPS.get(key, None) for key in final_want_bandwidth_settings_10_MBPS},
    "ONE_GBPS": {key: instance_id_bandwidth_settings_1_GBPS.get(key, None) for key in final_want_bandwidth_settings_1_GBPS},
    "ONE_MBPS": {key: instance_id_bandwidth_settings_1_MBPS.get(key, None) for key in final_want_bandwidth_settings_1_MBPS}
}

final_bandwidth_settings = {
    "HUNDRED_GBPS": final_want_bandwidth_settings_100_GBPS,
    "HUNDRED_MBPS": final_want_bandwidth_settings_100_MBPS,
    "TEN_GBPS": final_want_bandwidth_settings_10_GBPS,
    "TEN_MBPS": final_want_bandwidth_settings_10_MBPS,
    "ONE_GBPS": final_want_bandwidth_settings_1_GBPS,
    "ONE_MBPS": final_want_bandwidth_settings_1_MBPS
}

import json
# Generating the dynamic payload directly
# Extract DSCP settings from required details
# Extract DSCP settings from required details
want_dscp_settings = {key.upper(): value.upper() if isinstance(value, str) else value
                      for key, value in required_details['dscp_settings'].items()}

# Current DSCP settings from the current profiles
have_dscp_settings = {
    tc['trafficClass']: tc['dscp']
    for profile in current_profiles
    for clause in profile.get('clause', [])
    if 'tcDscpSettings' in clause
    for tc in clause['tcDscpSettings']
}

# Output the extracted data
print("\nWant DSCP Settings:")
print(want_dscp_settings)

print("\nHave DSCP Settings:")
print(have_dscp_settings)

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
print("Final Want DSCP Dict:")
print(final_want_dscp_dict)

# Initialize mapping for DSCP instance IDs
id_dscp_mapping = {}

# Map DSCP instance IDs from current profiles
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
    print("No updates required for DSCP settings. Both dictionaries match.")
else:
    print("Update required for DSCP settings.")

# Construct the payload for DSCP customization
instance_ids = {}
for profile in current_profiles:
    for clause in profile.get('clause', []):
        if 'type' in clause and clause['type'] == 'DSCP_CUSTOMIZATION':
            instance_ids['dscp'] = clause.get('instanceId')
        if 'interfaceSpeedBandwidthClauses' in clause and clause['interfaceSpeedBandwidthClauses']:
            instance_ids['bandwidth'] = clause.get('instanceId')

speed_to_instance_id = {}

# Loop through the current_profiles to extract the instanceId for each speed
for profile in current_profiles:
    for clause in profile.get('clause', []):
        if 'interfaceSpeedBandwidthClauses' in clause:
            for speed_bandwidth_clause in clause['interfaceSpeedBandwidthClauses']:
                speed = speed_bandwidth_clause.get('interfaceSpeed')
                instance_id = speed_bandwidth_clause.get('instanceId')
                
                # Store the instanceId in the dictionary with interfaceSpeed as the key
                if speed and instance_id:
                    speed_to_instance_id[speed] = instance_id
print(speed_to_instance_id)
import json

param = {
    "id": current_profiles[0].get("id"),
    "name": current_profiles[0].get("name"),
    "description": current_profiles[0].get("description"),
    "clause": []
}

# Loop through the speeds and bandwidth settings to create the clauses dynamically
for profile in current_profiles:
    for clause in profile.get('clause', []):
        if 'interfaceSpeedBandwidthClauses' in clause and clause['interfaceSpeedBandwidthClauses']:
            
            params = { 
                "instanceId": instance_ids.get("bandwidth"),
                "type": "BANDWIDTH",
                "isCommonBetweenAllInterfaceSpeeds": False,
                "interfaceSpeedBandwidthClauses": []
            }
            param["clause"].append(params)

            # Loop through the speeds and bandwidth settings for this profile
            for speed, bandwidth_settings in instance_id_bandwidth_settings.items():
                clause = {
                    "instanceId": speed_to_instance_id.get(speed) ,
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
                params["interfaceSpeedBandwidthClauses"].append(clause)

        if 'tcDscpSettings' in clause and clause['tcDscpSettings']:
            dscp_clause = {
                "instanceId": instance_ids.get("dscp"),
                "type": "DSCP_CUSTOMIZATION",
                "tcDscpSettings": []
            }

            for traffic_class, dscp_value in final_want_dscp_dict.items():
                dscp_clause["tcDscpSettings"].append({
                    "instanceId": id_dscp_mapping[traffic_class],
                    "trafficClass": traffic_class,
                    "dscp": dscp_value
                })

            # Add DSCP clause to the payload
            param["clause"].append(dscp_clause)

        # Add the generated param to the payload
        payload = [param]

# Print the result as a JSON string
print(json.dumps(payload, indent=2))




