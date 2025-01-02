required_details = {
  'profile_name': 'sample_q_p',
  'profile_description': 'sample desc',
  'bandwidth_settings': {
    'is_common_between_all_interface_speeds': False,
    'interface_speed_settings': [
      {
        'interface_speed': 'HUNDRED_GBPS',
        'bandwidth_percentages': {
          'transactional_data': '5',
          'best_effort': '10',
          'voip_telephony': '20',
          'multimedia_streaming': '5',
          'real_time_interactive': '20',
          'multimedia_conferencing': '10',
          'signaling': '11',
          'scavenger': '6',
          'ops_admin_mgmt': '5',
          'broadcast_video': '2',
          'network_control': '3',
          'bulk_data': '3'
        }
      },
      {
        'interface_speed': 'TEN_GBPS',
        'bandwidth_percentages': {
          'transactional_data': '5',
          'best_effort': '10',
          'voip_telephony': '20',
          'multimedia_streaming': '5',
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
      {
        'interface_speed': 'HUNDRED_MBPS',
        'bandwidth_percentages': {
          'transactional_data': '5',
          'best_effort': '10',
          'voip_telephony': '20',
          'multimedia_streaming': '5',
          'real_time_interactive': '19',
          'multimedia_conferencing': '11',
          'signaling': '10',
          'scavenger': '5',
          'ops_admin_mgmt': '5',
          'broadcast_video': '2',
          'network_control': '3',
          'bulk_data': '5'
        }
      },
      {
        'interface_speed': 'TEN_MBPS, ONE_MBPS, ONE_GBPS',
        'bandwidth_percentages': {
          'transactional_data': '5',
          'best_effort': '10',
          'voip_telephony': '20',
          'multimedia_streaming': '5',
          'real_time_interactive': '14',
          'multimedia_conferencing': '16',
          'signaling': '10',
          'scavenger': '5',
          'ops_admin_mgmt': '5',
          'broadcast_video': '2',
          'network_control': '3',
          'bulk_data': '5'
        }
      }
    ]
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
    'bulk_data': '21',
    'scavenger': '2',
    'real_time_interactive': '34'
  }
}

current_profiles = [
  {
    'id': 'f5528fa9-fb8e-4cfe-9d5f-423c328949e7',
    'instanceId': 15822218,
    'instanceCreatedOn': 1735641175406,
    'instanceUpdatedOn': 1735641175406,
    'instanceVersion': 0,
    'createTime': 1735641175388,
    'deployed': False,
    'description': 'sample desc',
    'isSeeded': False,
    'isStale': False,
    'lastUpdateTime': 1735641175388,
    'name': 'sample_q_p',
    'namespace': 'f5528fa9-fb8e-4cfe-9d5f-423c328949e7',
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
        'id': '197ea880-8237-42ab-ba65-ac2ac091942a',
        'instanceId': 131679615,
        'instanceCreatedOn': 1735641175406,
        'instanceUpdatedOn': 1735641175406,
        'instanceVersion': 0,
        'priority': 1,
        'isCommonBetweenAllInterfaceSpeeds': False,
        'interfaceSpeedBandwidthClauses': [
          {
            'id': '298933b7-9970-416a-a83d-1e8504ff6e14',
            'instanceId': 131681565,
            'instanceCreatedOn': 1735641175406,
            'instanceUpdatedOn': 1735641175406,
            'instanceVersion': 0,
            'interfaceSpeed': 'HUNDRED_MBPS',
            'tcBandwidthSettings': [
              {
                'id': 'f2c6e0a0-8999-494b-b619-5a4d254c150f',
                'instanceId': 131682731,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'OPS_ADMIN_MGMT',
                'displayName': '0'
              },
              {
                'id': '50f072f0-6a29-4297-881f-2e96285fc9c3',
                'instanceId': 131682733,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'BULK_DATA',
                'displayName': '0'
              },
              {
                'id': 'c67b8ca4-06bd-4ca4-9630-3b262fad86f4',
                'instanceId': 131682732,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 25,
                'trafficClass': 'REAL_TIME_INTERACTIVE',
                'displayName': '0'
              },
              {
                'id': '5ebce23a-b697-4a4a-b87f-c8aac1d9c2e8',
                'instanceId': 131682735,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'MULTIMEDIA_CONFERENCING',
                'displayName': '0'
              },
              {
                'id': '416e3cb0-4c8e-4e2c-909d-11937dbda4e3',
                'instanceId': 131682734,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'SCAVENGER',
                'displayName': '0'
              },
              {
                'id': '6dbe80d1-3b8c-44c6-9ddf-f9b385c5de61',
                'instanceId': 131682737,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 2,
                'trafficClass': 'BROADCAST_VIDEO',
                'displayName': '0'
              },
              {
                'id': 'a419a241-cccb-498e-bb13-6b906851f882',
                'instanceId': 131682736,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'SIGNALING',
                'displayName': '0'
              },
              {
                'id': 'cfdf0ecf-d6bc-4657-9a77-ab621f6e6a1a',
                'instanceId': 131682739,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'TRANSACTIONAL_DATA',
                'displayName': '0'
              },
              {
                'id': 'db990838-59b4-4e29-875e-dc206a5a5ffc',
                'instanceId': 131682738,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'BEST_EFFORT',
                'displayName': '0'
              },
              {
                'id': '5ee9b777-ae82-4f4b-b451-403970e3a193',
                'instanceId': 131682741,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 3,
                'trafficClass': 'NETWORK_CONTROL',
                'displayName': '0'
              },
              {
                'id': '6253c79b-e8e7-421e-bf6f-0abb596708ec',
                'instanceId': 131682740,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'VOIP_TELEPHONY',
                'displayName': '0'
              },
              {
                'id': 'c9f59ed2-83f1-4895-9f20-56feaa5e39f3',
                'instanceId': 131682742,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 15,
                'trafficClass': 'MULTIMEDIA_STREAMING',
                'displayName': '0'
              }
            ],
            'displayName': '0'
          },
          {
            'id': 'f20d67f6-9727-4312-bf96-bd9c86c387a5',
            'instanceId': 131681564,
            'instanceCreatedOn': 1735641175406,
            'instanceUpdatedOn': 1735641175406,
            'instanceVersion': 0,
            'interfaceSpeed': 'ONE_MBPS',
            'tcBandwidthSettings': [
              {
                'id': '5ab675ba-fe04-4bda-9fb3-5a38bc7cefc7',
                'instanceId': 131682729,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'SIGNALING',
                'displayName': '0'
              },
              {
                'id': 'f0f88bb4-f7b1-47d9-b9a6-30dd87b75114',
                'instanceId': 131682728,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'MULTIMEDIA_CONFERENCING',
                'displayName': '0'
              },
              {
                'id': '2b849e4c-a6a5-48a9-810a-0311cc289c4e',
                'instanceId': 131682730,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'OPS_ADMIN_MGMT',
                'displayName': '0'
              },
              {
                'id': 'c02f60c8-f33e-441b-82bd-9b37a0710693',
                'instanceId': 131682719,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'BEST_EFFORT',
                'displayName': '0'
              },
              {
                'id': '5205abe7-7ddf-4463-83ff-14e9c80ade7b',
                'instanceId': 131682721,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'SCAVENGER',
                'displayName': '0'
              },
              {
                'id': '835af21d-3364-4a08-aea9-38ddc075dcc6',
                'instanceId': 131682720,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'BULK_DATA',
                'displayName': '0'
              },
              {
                'id': '15586f08-d22f-4c41-b575-3225eb4c4f9c',
                'instanceId': 131682723,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 2,
                'trafficClass': 'BROADCAST_VIDEO',
                'displayName': '0'
              },
              {
                'id': '7c0460c5-f0d2-40b5-a2d0-fe0f66f717d4',
                'instanceId': 131682722,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'MULTIMEDIA_STREAMING',
                'displayName': '0'
              },
              {
                'id': '76a260a7-e015-4ac9-95b4-4f8ebcee5c32',
                'instanceId': 131682725,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'TRANSACTIONAL_DATA',
                'displayName': '0'
              },
              {
                'id': 'e93c1163-61cb-453a-b8c0-dcad9fa45373',
                'instanceId': 131682724,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 15,
                'trafficClass': 'VOIP_TELEPHONY',
                'displayName': '0'
              },
              {
                'id': '0e5d1e46-ebec-4b47-af2a-40026744064f',
                'instanceId': 131682727,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 20,
                'trafficClass': 'REAL_TIME_INTERACTIVE',
                'displayName': '0'
              },
              {
                'id': 'b16ec1a2-0d46-489e-a107-ee05f300e26f',
                'instanceId': 131682726,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 3,
                'trafficClass': 'NETWORK_CONTROL',
                'displayName': '0'
              }
            ],
            'displayName': '0'
          },
          {
            'id': 'f57661ba-602d-42ce-a7b3-20df025d0af9',
            'instanceId': 131681567,
            'instanceCreatedOn': 1735641175406,
            'instanceUpdatedOn': 1735641175406,
            'instanceVersion': 0,
            'interfaceSpeed': 'TEN_MBPS',
            'tcBandwidthSettings': [
              {
                'id': 'a96091f6-7e8c-4cb0-bf2c-4ee8fbbf9e1d',
                'instanceId': 131682761,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'MULTIMEDIA_STREAMING',
                'displayName': '0'
              },
              {
                'id': '6068b235-3449-4e48-9a72-7490692c4e67',
                'instanceId': 131682760,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 20,
                'trafficClass': 'REAL_TIME_INTERACTIVE',
                'displayName': '0'
              },
              {
                'id': '05ef7b1b-64bd-4684-a232-b3ef01417ca9',
                'instanceId': 131682763,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 3,
                'trafficClass': 'NETWORK_CONTROL',
                'displayName': '0'
              },
              {
                'id': '42ba3f8a-399e-459b-92be-243f237a3c32',
                'instanceId': 131682762,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'BEST_EFFORT',
                'displayName': '0'
              },
              {
                'id': '554227af-0422-458c-a52c-0ac0ea6b84ba',
                'instanceId': 131682765,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'SCAVENGER',
                'displayName': '0'
              },
              {
                'id': 'dbea6e7c-46e6-49c4-9653-4b2234f19db5',
                'instanceId': 131682764,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'MULTIMEDIA_CONFERENCING',
                'displayName': '0'
              },
              {
                'id': '8e668e8e-8e32-492e-88cb-6e96a503fcd3',
                'instanceId': 131682766,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'TRANSACTIONAL_DATA',
                'displayName': '0'
              },
              {
                'id': 'ee1029c5-676f-478c-8482-ac31175f1c8a',
                'instanceId': 131682755,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 15,
                'trafficClass': 'VOIP_TELEPHONY',
                'displayName': '0'
              },
              {
                'id': '1dbca5a8-bff4-441e-bbd3-0f884a9575bc',
                'instanceId': 131682757,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'SIGNALING',
                'displayName': '0'
              },
              {
                'id': '2c2adb1b-9ee0-4372-9634-90f12a60ac2b',
                'instanceId': 131682756,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'BULK_DATA',
                'displayName': '0'
              },
              {
                'id': '0ef572d5-7815-4b08-a173-85e9b02ccb91',
                'instanceId': 131682759,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 2,
                'trafficClass': 'BROADCAST_VIDEO',
                'displayName': '0'
              },
              {
                'id': 'de3071dd-4260-4585-ae61-80e7b811f8be',
                'instanceId': 131682758,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'OPS_ADMIN_MGMT',
                'displayName': '0'
              }
            ],
            'displayName': '0'
          },
          {
            'id': '7845b25c-cb9a-4c51-9df8-d8e8e55422e8',
            'instanceId': 131681566,
            'instanceCreatedOn': 1735641175406,
            'instanceUpdatedOn': 1735641175406,
            'instanceVersion': 0,
            'interfaceSpeed': 'TEN_GBPS',
            'tcBandwidthSettings': [
              {
                'id': '0ee6b47a-e3a3-4512-b1d1-f8065b850e5b',
                'instanceId': 131682745,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'MULTIMEDIA_CONFERENCING',
                'displayName': '0'
              },
              {
                'id': '5578fae5-53af-4676-90e1-29b246da83a0',
                'instanceId': 131682744,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'SCAVENGER',
                'displayName': '0'
              },
              {
                'id': 'f76248e2-b6a8-4825-818e-33b0a8dec809',
                'instanceId': 131682747,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'BEST_EFFORT',
                'displayName': '0'
              },
              {
                'id': 'a3d77dca-64a3-4791-a960-8c9a188c3a56',
                'instanceId': 131682746,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 25,
                'trafficClass': 'VOIP_TELEPHONY',
                'displayName': '0'
              },
              {
                'id': '9967ae11-d0a0-4354-bcf9-46e6f0d9b3df',
                'instanceId': 131682749,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 20,
                'trafficClass': 'REAL_TIME_INTERACTIVE',
                'displayName': '0'
              },
              {
                'id': '916e9516-077a-4ffd-96d5-c4b218c57c6d',
                'instanceId': 131682748,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'TRANSACTIONAL_DATA',
                'displayName': '0'
              },
              {
                'id': '5660258c-bd82-4082-b965-28a94bc31bf9',
                'instanceId': 131682751,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 3,
                'trafficClass': 'NETWORK_CONTROL',
                'displayName': '0'
              },
              {
                'id': 'd85d99d2-be76-4dcb-8ac1-d87c4fa3c9f3',
                'instanceId': 131682750,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 4,
                'trafficClass': 'OPS_ADMIN_MGMT',
                'displayName': '0'
              },
              {
                'id': '2478cecb-7020-4d15-8dd5-ec60189e7a84',
                'instanceId': 131682753,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 2,
                'trafficClass': 'BROADCAST_VIDEO',
                'displayName': '0'
              },
              {
                'id': 'febc7d32-bf91-452f-b1cb-8781b356d41a',
                'instanceId': 131682752,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 6,
                'trafficClass': 'SIGNALING',
                'displayName': '0'
              },
              {
                'id': '65d7e1d9-a395-4c92-a455-eceeeae36f63',
                'instanceId': 131682754,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 15,
                'trafficClass': 'BULK_DATA',
                'displayName': '0'
              },
              {
                'id': '03cee86d-8538-4a2d-8807-d3f4f309380c',
                'instanceId': 131682743,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'MULTIMEDIA_STREAMING',
                'displayName': '0'
              }
            ],
            'displayName': '0'
          },
          {
            'id': '1363b6dd-6e17-468f-ad1d-b0e3da82dd5f',
            'instanceId': 131681569,
            'instanceCreatedOn': 1735641175406,
            'instanceUpdatedOn': 1735641175406,
            'instanceVersion': 0,
            'interfaceSpeed': 'ONE_GBPS',
            'tcBandwidthSettings': [
              {
                'id': '7fb56056-3681-4d0a-96aa-d4300108016a',
                'instanceId': 131682779,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'BULK_DATA',
                'displayName': '0'
              },
              {
                'id': 'a381e4b9-c3e0-4677-9dfa-85249df0d3ee',
                'instanceId': 131682781,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'TRANSACTIONAL_DATA',
                'displayName': '0'
              },
              {
                'id': '442dfba9-b78f-414c-8547-781a4e45e54a',
                'instanceId': 131682780,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'MULTIMEDIA_STREAMING',
                'displayName': '0'
              },
              {
                'id': '2a15c5f7-cb86-45d6-b5ea-2c789109f12c',
                'instanceId': 131682783,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'OPS_ADMIN_MGMT',
                'displayName': '0'
              },
              {
                'id': 'e756ea11-ed3b-4770-b889-fc9b1b56f6cd',
                'instanceId': 131682782,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 2,
                'trafficClass': 'BROADCAST_VIDEO',
                'displayName': '0'
              },
              {
                'id': '1508fe8c-3ff1-4846-9475-249b7c006f7c',
                'instanceId': 131682785,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'SIGNALING',
                'displayName': '0'
              },
              {
                'id': 'd7ec7aa7-4099-4d16-b449-f31cf4ae8329',
                'instanceId': 131682784,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 20,
                'trafficClass': 'REAL_TIME_INTERACTIVE',
                'displayName': '0'
              },
              {
                'id': '985f15ff-3235-43b4-b08b-3fcee4483d71',
                'instanceId': 131682787,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'BEST_EFFORT',
                'displayName': '0'
              },
              {
                'id': 'e8fcdf8e-0779-4036-b027-338a39fcb638',
                'instanceId': 131682786,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'MULTIMEDIA_CONFERENCING',
                'displayName': '0'
              },
              {
                'id': 'afeafc93-0440-40c9-9c56-3fd1092918e2',
                'instanceId': 131682789,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 3,
                'trafficClass': 'NETWORK_CONTROL',
                'displayName': '0'
              },
              {
                'id': 'c5e7baad-f0e0-4102-8231-8c1489b2a8a3',
                'instanceId': 131682788,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'SCAVENGER',
                'displayName': '0'
              },
              {
                'id': '2787147f-f4fe-45c4-9860-93b80a2f852d',
                'instanceId': 131682790,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 15,
                'trafficClass': 'VOIP_TELEPHONY',
                'displayName': '0'
              }
            ],
            'displayName': '0'
          },
          {
            'id': '2e515dd0-275a-4061-bd13-894775292aa4',
            'instanceId': 131681568,
            'instanceCreatedOn': 1735641175406,
            'instanceUpdatedOn': 1735641175406,
            'instanceVersion': 0,
            'interfaceSpeed': 'HUNDRED_GBPS',
            'tcBandwidthSettings': [
              {
                'id': 'b3682e9f-de33-4323-8cc5-5b56bd882959',
                'instanceId': 131682777,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 3,
                'trafficClass': 'NETWORK_CONTROL',
                'displayName': '0'
              },
              {
                'id': '317c5866-fac3-4891-888f-22491702667b',
                'instanceId': 131682776,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'OPS_ADMIN_MGMT',
                'displayName': '0'
              },
              {
                'id': 'c02e785a-8cfb-4e93-a1fd-a607a8fa2004',
                'instanceId': 131682778,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'TRANSACTIONAL_DATA',
                'displayName': '0'
              },
              {
                'id': 'cbbdd551-93b9-4544-aa17-d0833c10e7ac',
                'instanceId': 131682767,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'BULK_DATA',
                'displayName': '0'
              },
              {
                'id': '56e5c0d7-6b6d-410e-a95c-e2336a5da786',
                'instanceId': 131682769,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'BEST_EFFORT',
                'displayName': '0'
              },
              {
                'id': 'e64f6f70-3bc8-419f-88a8-8e5f79c4ff85',
                'instanceId': 131682768,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 2,
                'trafficClass': 'BROADCAST_VIDEO',
                'displayName': '0'
              },
              {
                'id': '2efc6f73-2b37-4510-ace6-4d42271ba151',
                'instanceId': 131682771,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 20,
                'trafficClass': 'VOIP_TELEPHONY',
                'displayName': '0'
              },
              {
                'id': '5bbdcc9b-0bce-47d0-9d8c-f1aade781a9b',
                'instanceId': 131682770,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'MULTIMEDIA_STREAMING',
                'displayName': '0'
              },
              {
                'id': 'f6ad4fe1-f52e-42dc-8c49-f8f7a91c3005',
                'instanceId': 131682773,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'MULTIMEDIA_CONFERENCING',
                'displayName': '0'
              },
              {
                'id': 'b99a8c88-8350-4779-8288-2d3d1bfcd7d0',
                'instanceId': 131682772,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 20,
                'trafficClass': 'REAL_TIME_INTERACTIVE',
                'displayName': '0'
              },
              {
                'id': 'be314a7d-f81c-44a0-8886-a54b42f4e8f0',
                'instanceId': 131682775,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 5,
                'trafficClass': 'SCAVENGER',
                'displayName': '0'
              },
              {
                'id': '9930e298-aef9-475a-84de-7fbd010d8a9a',
                'instanceId': 131682774,
                'instanceCreatedOn': 1735641175406,
                'instanceUpdatedOn': 1735641175406,
                'instanceVersion': 0,
                'bandwidthPercentage': 10,
                'trafficClass': 'SIGNALING',
                'displayName': '0'
              }
            ],
            'displayName': '0'
          }
        ],
        'displayName': '0'
      },
      {
        'id': 'fab5f5cd-0ae2-4d48-9b7c-2a063fe54ba9',
        'instanceId': 131679616,
        'instanceCreatedOn': 1735641175406,
        'instanceUpdatedOn': 1735641175406,
        'instanceVersion': 0,
        'priority': 1,
        'type': 'DSCP_CUSTOMIZATION',
        'tcDscpSettings': [
          {
            'id': 'ba5e6260-a74a-4324-9528-97859e74f6bc',
            'instanceId': 131680617,
            'instanceCreatedOn': 1735641175406,
            'instanceUpdatedOn': 1735641175406,
            'instanceVersion': 0,
            'dscp': '28',
            'trafficClass': 'TRANSACTIONAL_DATA',
            'displayName': '0'
          },
          {
            'id': '2ee33e40-6ee1-4b17-9223-8cae52bfc44a',
            'instanceId': 131680616,
            'instanceCreatedOn': 1735641175406,
            'instanceUpdatedOn': 1735641175406,
            'instanceVersion': 0,
            'dscp': '34',
            'trafficClass': 'REAL_TIME_INTERACTIVE',
            'displayName': '0'
          },
          {
            'id': '6a382505-f01e-4b0d-afc1-f44e71f6192a',
            'instanceId': 131680619,
            'instanceCreatedOn': 1735641175406,
            'instanceUpdatedOn': 1735641175406,
            'instanceVersion': 0,
            'dscp': '45',
            'trafficClass': 'VOIP_TELEPHONY',
            'displayName': '0'
          },
          {
            'id': '5bf07644-4d58-4f9e-8709-d4b8d407bf1f',
            'instanceId': 131680618,
            'instanceCreatedOn': 1735641175406,
            'instanceUpdatedOn': 1735641175406,
            'instanceVersion': 0,
            'dscp': '27',
            'trafficClass': 'MULTIMEDIA_STREAMING',
            'displayName': '0'
          },
          {
            'id': '9b768c63-bbf3-40e1-a3e3-73d12790236a',
            'instanceId': 131680620,
            'instanceCreatedOn': 1735641175406,
            'instanceUpdatedOn': 1735641175406,
            'instanceVersion': 0,
            'dscp': '20',
            'trafficClass': 'MULTIMEDIA_CONFERENCING',
            'displayName': '0'
          },
          {
            'id': '418668e4-a7a5-4b72-aa58-76313a1f385f',
            'instanceId': 131680609,
            'instanceCreatedOn': 1735641175406,
            'instanceUpdatedOn': 1735641175406,
            'instanceVersion': 0,
            'dscp': '0',
            'trafficClass': 'BEST_EFFORT',
            'displayName': '0'
          },
          {
            'id': '04575468-b3b5-4504-80e3-75ad8c03955a',
            'instanceId': 131680611,
            'instanceCreatedOn': 1735641175406,
            'instanceUpdatedOn': 1735641175406,
            'instanceVersion': 0,
            'dscp': '10',
            'trafficClass': 'BULK_DATA',
            'displayName': '0'
          },
          {
            'id': '5454ac3a-3b16-4cc8-8de3-a92b2119395d',
            'instanceId': 131680610,
            'instanceCreatedOn': 1735641175406,
            'instanceUpdatedOn': 1735641175406,
            'instanceVersion': 0,
            'dscp': '46',
            'trafficClass': 'BROADCAST_VIDEO',
            'displayName': '0'
          },
          {
            'id': '13993f44-3e3f-4906-b590-ebc09857973c',
            'instanceId': 131680613,
            'instanceCreatedOn': 1735641175406,
            'instanceUpdatedOn': 1735641175406,
            'instanceVersion': 0,
            'dscp': '4',
            'trafficClass': 'SIGNALING',
            'displayName': '0'
          },
          {
            'id': 'd31911a8-26a2-4760-9f27-3a40eefcf3bd',
            'instanceId': 131680612,
            'instanceCreatedOn': 1735641175406,
            'instanceUpdatedOn': 1735641175406,
            'instanceVersion': 0,
            'dscp': '23',
            'trafficClass': 'OPS_ADMIN_MGMT',
            'displayName': '0'
          },
          {
            'id': 'e6988f57-ae00-40cf-8a83-70667005c3d3',
            'instanceId': 131680615,
            'instanceCreatedOn': 1735641175406,
            'instanceUpdatedOn': 1735641175406,
            'instanceVersion': 0,
            'dscp': '48',
            'trafficClass': 'NETWORK_CONTROL',
            'displayName': '0'
          },
          {
            'id': '3850e475-5ad3-4932-bfff-8982cf399ab2',
            'instanceId': 131680614,
            'instanceCreatedOn': 1735641175406,
            'instanceUpdatedOn': 1735641175406,
            'instanceVersion': 0,
            'dscp': '2',
            'trafficClass': 'SCAVENGER',
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




