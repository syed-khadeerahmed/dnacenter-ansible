# Input data
# required_queuing_profile_details = {'application_queuing_details': [{'queuing_profile_name': 'Asampleq2', 'queuing_policy_description': 'sample 12234567876543q', 'bandwidth_settings': {'is_common_between_all_interface_speeds': True, 'interface_speed': 'ALL', 'bandwidth_percentages': {'transactional_data': '5', 'best_effort': '10', 'voip_telephony': '15', 'multimedia_streaming': '10', 'real_time_interactive': '20', 'multimedia_conferencing': '9', 'signaling': '11', 'scavenger': '5', 'ops_admin_mgmt': '5', 'broadcast_video': '2', 'network_control': '3', 'bulk_data': '5'}}, 'dscp_settings': {'multimedia_conferencing': '20', 'ops_admin_mgmt': '26', 'transactional_data': '28', 'voip_telephony': '45', 'multimedia_streaming': '27', 'broadcast_video': '46', 'network_control': '48', 'best_effort': '0', 'signaling': '4', 'bulk_data': '10', 'scavenger': '2', 'real_time_interactive': '34'}}], 'application_set_details': None, 'application_details': None} 
# queuing_profile = {'current_queuing_profile': [{'id': '7928ec20-244d-4694-b6ab-4b18a4ae71fe', 'instanceId': 330907317, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'createTime': 1733465660955, 'deployed': False, 'description': 'sample 12234567876543q', 'isSeeded': False, 'isStale': False, 'lastUpdateTime': 1733465660955, 'name': 'Asampleq2', 'namespace': '7928ec20-244d-4694-b6ab-4b18a4ae71fe', 'provisioningState': 'DEFINED', 'qualifier': 'application', 'resourceVersion': 0, 'targetIdList': [], 'type': 'contract', 'cfsChangeInfo': [], 'customProvisions': [], 'externalIntentSourceInfos': [], 'genId': 0, 'internal': False, 'isDeleted': False, 'iseReserved': False, 'pushed': False, 'clause': [{'id': '649eba3b-5bcc-4bfd-9c4c-541723ed6e17', 'instanceId': 330986164, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'priority': 1, 'type': 'BANDWIDTH', 'isCommonBetweenAllInterfaceSpeeds': True, 'interfaceSpeedBandwidthClauses': [{'id': 'f1ba0559-4a0e-41e5-ae4d-fbe964bf2638', 'instanceId': 334923690, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'interfaceSpeed': 'ALL', 'tcBandwidthSettings': [{'id': '4014c0be-fd4b-47fd-87c8-9c23b4b4bb51', 'instanceId': 403980788, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 20, 'trafficClass': 'REAL_TIME_INTERACTIVE', 'displayName': '0'}, {'id': '0fd4542e-ea8e-4eca-a357-81d51215f2c9', 'instanceId': 403980789, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 15, 'trafficClass': 'VOIP_TELEPHONY', 'displayName': '0'}, {'id': '976e5ecb-fcf2-42a0-b22d-23e7701acfe3', 'instanceId': 403980790, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 5, 'trafficClass': 'TRANSACTIONAL_DATA', 'displayName': '0'}, {'id': '612b4493-4ac9-4d42-b550-aee55774e8f4', 'instanceId': 403980791, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 5, 'trafficClass': 'SCAVENGER', 'displayName': '0'}, {'id': '7f3942b5-5bc4-4982-a91d-6c9ff9b6896d', 'instanceId': 403980796, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 10, 'trafficClass': 'BEST_EFFORT', 'displayName': '0'}, {'id': '4e4904d5-8d49-4b8d-bba5-57bfd2ae7940', 'instanceId': 403980797, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 2, 'trafficClass': 'BROADCAST_VIDEO', 'displayName': '0'}, {'id': '415f6306-b45d-49a5-86df-ea8d247ad284', 'instanceId': 403980798, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 10, 'trafficClass': 'MULTIMEDIA_CONFERENCING', 'displayName': '0'}, {'id': '5eccf79c-81a7-4246-b21e-168150daf7f3', 'instanceId': 403980799, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 10, 'trafficClass': 'MULTIMEDIA_STREAMING', 'displayName': '0'}, {'id': 'f1a93051-32eb-4f1a-a16c-e3538b935f93', 'instanceId': 403980792, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 3, 'trafficClass': 'NETWORK_CONTROL', 'displayName': '0'}, {'id': '537708aa-ba4f-4215-b8d1-771bf6c555d4', 'instanceId': 403980793, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 5, 'trafficClass': 'OPS_ADMIN_MGMT', 'displayName': '0'}, {'id': '9e7ad1cf-579a-4289-a78b-9fd7f69d6fa3', 'instanceId': 403980794, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 10, 'trafficClass': 'SIGNALING', 'displayName': '0'}, {'id': '0cd3587a-ac90-4151-973b-e4fb031d8213', 'instanceId': 403980795, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'bandwidthPercentage': 5, 'trafficClass': 'BULK_DATA', 'displayName': '0'}], 'displayName': '0'}], 'displayName': '0'}, {'id': '76cf7587-2f4d-4d6a-b9dc-e8be08f4faf8', 'instanceId': 330986165, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'priority': 1, 'type': 'DSCP_CUSTOMIZATION', 'tcDscpSettings': [{'id': '52451cc7-0767-40df-a276-d6f04f85558b', 'instanceId': 330986922, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '20', 'trafficClass': 'MULTIMEDIA_CONFERENCING', 'displayName': '0'}, {'id': '688a42fe-0bf4-47e8-8697-ba9a62f60735', 'instanceId': 330986923, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '28', 'trafficClass': 'TRANSACTIONAL_DATA', 'displayName': '0'}, {'id': 'b52e007f-f759-4812-8588-f4eefc881f67', 'instanceId': 330986920, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '34', 'trafficClass': 'REAL_TIME_INTERACTIVE', 'displayName': '0'}, {'id': 'd5cc42b9-3f70-4171-a6ed-3844055cac2a', 'instanceId': 330986921, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '48', 'trafficClass': 'NETWORK_CONTROL', 'displayName': '0'}, {'id': 'f57198f3-0290-4e8f-80f1-10310b083073', 'instanceId': 330986926, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '4', 'trafficClass': 'SIGNALING', 'displayName': '0'}, {'id': '7ada76ed-33db-464c-9261-354ae8851e64', 'instanceId': 330986927, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '45', 'trafficClass': 'VOIP_TELEPHONY', 'displayName': '0'}, {'id': 'f7da2e64-ad3d-452a-95c4-ee0cd692032d', 'instanceId': 330986924, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '23', 'trafficClass': 'OPS_ADMIN_MGMT', 'displayName': '0'}, {'id': '07eb0441-463c-49af-bf3b-3876d929d994', 'instanceId': 330986925, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '10', 'trafficClass': 'BULK_DATA', 'displayName': '0'}, {'id': 'be7ccba3-c763-4de9-96e0-2090a9730c63', 'instanceId': 330986930, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '46', 'trafficClass': 'BROADCAST_VIDEO', 'displayName': '0'}, {'id': '144ee1c9-2c11-45fa-8c5f-508b88bf22b9', 'instanceId': 330986931, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '2', 'trafficClass': 'SCAVENGER', 'displayName': '0'}, {'id': 'd0701f12-ccb3-4ccc-a0f1-97efa7669d82', 'instanceId': 330986928, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '0', 'trafficClass': 'BEST_EFFORT', 'displayName': '0'}, {'id': '32e63093-5001-4835-be12-322d01fa857a', 'instanceId': 330986929, 'instanceCreatedOn': 1733465660964, 'instanceUpdatedOn': 1733465660964, 'instanceVersion': 0, 'dscp': '27', 'trafficClass': 'MULTIMEDIA_STREAMING', 'displayName': '0'}], 'displayName': '0'}], 'contractClassifier': [], 'displayName': '0'}], 'queuing_profile_exists': True} 


# queuing_profile = {
#   'current_queuing_profile': [
#     {
#   'id': '066fbc12-b17e-46d4-aa67-49156f994e5a',
#   'instanceId': 330906938,
#   'instanceCreatedOn': 1732164727952,
#   'instanceUpdatedOn': 1732164727952,
#   'instanceVersion': 1,
#   'createTime': 1732164727945,
#   'deployed': False,
#   'description': 'This is a sample test description',
#   'isSeeded': False,
#   'isStale': False,
#   'lastUpdateTime': 1732171051987,
#   'name': 'QueueingProfileNew1',
#   'namespace': '066fbc12-b17e-46d4-aa67-49156f994e5a',
#   'provisioningState': 'DEFINED',
#   'qualifier': 'application',
#   'resourceVersion': 1,
#   'targetIdList': [
    
#   ],
#   'type': 'contract',
#   'cfsChangeInfo': [
    
#   ],
#   'customProvisions': [
    
#   ],
#   'externalIntentSourceInfos': [
    
#   ],
#   'genId': 0,
#   'internal': False,
#   'isDeleted': False,
#   'iseReserved': False,
#   'pushed': False,
#   'clause': [
#     {
#       'id': '793d741f-a103-41f3-a404-f2dc4906f284',
#       'instanceId': 330985842,
#       'type': 'BANDWIDTH',
#       'isCommonBetweenAllInterfaceSpeeds': False,
#       'interfaceSpeedBandwidthClauses': [
#         {
#           'id': '150cc0c0-c1fa-4eef-9b23-b6565ebe2033',
#           'instanceId': 334923602,
#           'interfaceSpeed': 'HUNDRED_GBPS',
#           'tcBandwidthSettings': [
#             {
#               'id': '4ce20c0b-f882-4ea8-bba7-0798c8e438dc',
#               'instanceId': 334924756,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'MULTIMEDIA_CONFERENCING',
#             },
#             {
#               'id': 'c32ad2d9-9472-466b-9123-958e331f643f',
#               'instanceId': 334924757,
#               'bandwidthPercentage': 5,
#               'trafficClass': 'BULK_DATA',
#             },
#             {
#               'id': '146d06a6-1a58-4926-b499-f6e42a8c5c51',
#               'instanceId': 334924754,
#               'bandwidthPercentage': 5,
#               'trafficClass': 'OPS_ADMIN_MGMT',
#               'displayName': '0'
#             },
#             {
#               'id': '0839ae66-a768-411e-bf29-6cefadb4eba1',
#               'instanceId': 334924755,
#               'bandwidthPercentage': 5,
#               'trafficClass': 'BROADCAST_VIDEO',
#               'displayName': '0'
#             },
#             {
#               'id': '36419b7f-8c0c-4ea8-8310-6bb2543d98d2',
#               'instanceId': 334924752,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'VOIP_TELEPHONY',
#               'displayName': '0'
#             },
#             {
#               'id': 'fc2d6da3-1393-4632-9e65-29b9446457c0',
#               'instanceId': 334924753,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'NETWORK_CONTROL',
#               'displayName': '0'
#             },
#             {
#               'id': 'a6387f8f-2b1b-484e-a10f-0e6303e208dc',
#               'instanceId': 334924750,
#               'bandwidthPercentage': 5,
#               'trafficClass': 'SIGNALING',
#               'displayName': '0'
#             },
#             {
#               'id': 'f27f3ee5-5aed-413c-b5d0-43a0ed14592a',
#               'instanceId': 334924751,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'TRANSACTIONAL_DATA',
#               'displayName': '0'
#             },
#             {
#               'id': 'b590100d-d25b-4be3-b6c6-5afe03686315',
#               'instanceId': 334924748,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'SCAVENGER',
#               'displayName': '0'
#             },
#             {
#               'id': '8a30e273-b4a9-465e-84eb-770ec64666d4',
#               'instanceId': 334924749,
#               'bandwidthPercentage': 15,
#               'trafficClass': 'BEST_EFFORT',
#               'displayName': '0'
#             },
#             {
#               'id': '32dee7a8-6d35-431b-8ded-9a7864cf649a',
#               'instanceId': 334924746,
#               'bandwidthPercentage': 5,
#               'trafficClass': 'MULTIMEDIA_STREAMING',
#               'displayName': '0'
#             },
#             {
#               'id': 'f9e4915a-92b4-4a28-88f5-68f402cad2ed',
#               'instanceId': 334924747,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'REAL_TIME_INTERACTIVE',
#               'displayName': '0'
#             }
#           ],
#           'displayName': '0'
#         },
#         {
#           'id': 'accb8d11-eeb8-4de5-a988-966e77163b4c',
#           'instanceId': 334923603,
#           'instanceCreatedOn': 1732171051995,
#           'instanceUpdatedOn': 1732171051995,
#           'instanceVersion': 0,
#           'interfaceSpeed': 'HUNDRED_MBPS',
#           'tcBandwidthSettings': [
#             {
#               'id': '4153db5f-867c-4e7c-9dbd-2cb2c1e14e1e',
#               'instanceId': 334924758,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 15,
#               'trafficClass': 'BEST_EFFORT',
#               'displayName': '0'
#             },
#             {
#               'id': 'a122bd00-7a49-42a1-a62b-cf587dd92147',
#               'instanceId': 334924759,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'VOIP_TELEPHONY',
#               'displayName': '0'
#             },
#             {
#               'id': 'a352391f-8f71-472f-85d6-5e27d2b5953f',
#               'instanceId': 334924768,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 5,
#               'trafficClass': 'BULK_DATA',
#               'displayName': '0'
#             },
#             {
#               'id': '06de6833-0704-4e51-bfea-bfe10e5a12b8',
#               'instanceId': 334924769,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'NETWORK_CONTROL',
#               'displayName': '0'
#             },
#             {
#               'id': '01ff5d5d-e355-4e85-8706-b7b8dc15b98d',
#               'instanceId': 334924766,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 5,
#               'trafficClass': 'OPS_ADMIN_MGMT',
#               'displayName': '0'
#             },
#             {
#               'id': 'b445c657-0ba8-47a6-bebf-5871ebe2cfb8',
#               'instanceId': 334924767,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 5,
#               'trafficClass': 'BROADCAST_VIDEO',
#               'displayName': '0'
#             },
#             {
#               'id': 'd905ab5c-7fbb-41c3-9019-707be0bb0b22',
#               'instanceId': 334924764,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 5,
#               'trafficClass': 'MULTIMEDIA_STREAMING',
#               'displayName': '0'
#             },
#             {
#               'id': '6973b3ff-a925-4fad-85cd-dfdefad00876',
#               'instanceId': 334924765,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'MULTIMEDIA_CONFERENCING',
#               'displayName': '0'
#             },
#             {
#               'id': 'febd335e-2a99-49e4-b977-31004d310db6',
#               'instanceId': 334924762,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 5,
#               'trafficClass': 'SIGNALING',
#               'displayName': '0'
#             },
#             {
#               'id': '1868539b-2573-4891-9e33-c13aa4166081',
#               'instanceId': 334924763,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'REAL_TIME_INTERACTIVE',
#               'displayName': '0'
#             },
#             {
#               'id': 'f97a787c-33e4-4266-9ab5-c664f79f3808',
#               'instanceId': 334924760,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'TRANSACTIONAL_DATA',
#               'displayName': '0'
#             },
#             {
#               'id': 'a0d84bf3-bdc0-47d0-8629-710b05f850bf',
#               'instanceId': 334924761,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'SCAVENGER',
#               'displayName': '0'
#             }
#           ],
#           'displayName': '0'
#         },
#         {
#           'id': 'ded00286-7fbc-4655-b589-1183fab4510c',
#           'instanceId': 334923600,
#           'instanceCreatedOn': 1732171051995,
#           'instanceUpdatedOn': 1732171051995,
#           'instanceVersion': 0,
#           'interfaceSpeed': 'ONE_MBPS',
#           'tcBandwidthSettings': [
#             {
#               'id': 'f3e0af09-a34a-48cb-81dc-26dd6984aaa7',
#               'instanceId': 334924726,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'REAL_TIME_INTERACTIVE',
#               'displayName': '0'
#             },
#             {
#               'id': '5f826877-a386-4b96-834c-87e78ece908e',
#               'instanceId': 334924727,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'MULTIMEDIA_CONFERENCING',
#               'displayName': '0'
#             },
#             {
#               'id': '77f71782-49f9-4d54-a381-4b750a24190f',
#               'instanceId': 334924724,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'TRANSACTIONAL_DATA',
#               'displayName': '0'
#             },
#             {
#               'id': '1c2b4c70-da5a-47c7-9b34-4833b7fd5e83',
#               'instanceId': 334924725,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 5,
#               'trafficClass': 'BULK_DATA',
#               'displayName': '0'
#             },
#             {
#               'id': 'e5549566-0f55-4238-8be9-b8b6c52c7c32',
#               'instanceId': 334924722,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'NETWORK_CONTROL',
#               'displayName': '0'
#             },
#             {
#               'id': '2b242126-f03a-4e9a-af34-e594d0a337e0',
#               'instanceId': 334924723,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 15,
#               'trafficClass': 'BEST_EFFORT',
#               'displayName': '0'
#             },
#             {
#               'id': 'f5833e90-aa68-4d71-a1bd-cd74f9a18ace',
#               'instanceId': 334924732,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 5,
#               'trafficClass': 'OPS_ADMIN_MGMT',
#               'displayName': '0'
#             },
#             {
#               'id': '92e455aa-6269-48a3-a880-83f447a0846f',
#               'instanceId': 334924733,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 5,
#               'trafficClass': 'SIGNALING',
#               'displayName': '0'
#             },
#             {
#               'id': '33cfdcc4-59c5-4d85-8287-7e77827afaaf',
#               'instanceId': 334924730,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'VOIP_TELEPHONY',
#               'displayName': '0'
#             },
#             {
#               'id': '0f83de84-116b-41cf-9fa3-c2e854c599a3',
#               'instanceId': 334924731,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 5,
#               'trafficClass': 'MULTIMEDIA_STREAMING',
#               'displayName': '0'
#             },
#             {
#               'id': '15410c2b-3461-4fd4-afad-4f343153d737',
#               'instanceId': 334924728,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'SCAVENGER',
#               'displayName': '0'
#             },
#             {
#               'id': 'ff60331b-43b4-4ef3-a8e3-1d45b8489eaf',
#               'instanceId': 334924729,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 5,
#               'trafficClass': 'BROADCAST_VIDEO',
#               'displayName': '0'
#             }
#           ],
#           'displayName': '0'
#         },
#         {
#           'id': 'f89b6dc5-bb24-4ab4-9f38-d20b85e0df2e',
#           'instanceId': 334923601,
#           'instanceCreatedOn': 1732171051995,
#           'instanceUpdatedOn': 1732171051995,
#           'instanceVersion': 0,
#           'interfaceSpeed': 'ONE_GBPS',
#           'tcBandwidthSettings': [
#             {
#               'id': '00007150-596e-44aa-bc92-1a7aa2fa234e',
#               'instanceId': 334924742,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'MULTIMEDIA_CONFERENCING',
#               'displayName': '0'
#             },
#             {
#               'id': 'ee2fd798-d7a8-4516-af0f-4cf690fbfb15',
#               'instanceId': 334924743,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'VOIP_TELEPHONY',
#               'displayName': '0'
#             },
#             {
#               'id': '654a43d7-997a-4d25-882d-eb6119c2752a',
#               'instanceId': 334924740,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 5,
#               'trafficClass': 'BULK_DATA',
#               'displayName': '0'
#             },
#             {
#               'id': 'fe7f1365-c37f-44a7-8fbf-5b18b525ed76',
#               'instanceId': 334924741,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'REAL_TIME_INTERACTIVE',
#               'displayName': '0'
#             },
#             {
#               'id': '5507692f-22e3-4922-a73f-ce3d6cb3005c',
#               'instanceId': 334924738,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 15,
#               'trafficClass': 'BEST_EFFORT',
#               'displayName': '0'
#             },
#             {
#               'id': '3d7b7a20-6025-43b7-be73-15b61e4f3c59',
#               'instanceId': 334924739,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'SCAVENGER',
#               'displayName': '0'
#             },
#             {
#               'id': 'd65ae32c-1baa-42cd-89bb-3334e338e3ec',
#               'instanceId': 334924736,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 5,
#               'trafficClass': 'OPS_ADMIN_MGMT',
#               'displayName': '0'
#             },
#             {
#               'id': '88c9f417-35fe-4ae7-bba9-b8984c27f27c',
#               'instanceId': 334924737,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 5,
#               'trafficClass': 'SIGNALING',
#               'displayName': '0'
#             },
#             {
#               'id': 'ac35566e-63cc-4521-8147-d68d71933269',
#               'instanceId': 334924734,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'TRANSACTIONAL_DATA',
#               'displayName': '0'
#             },
#             {
#               'id': '9ec17242-82c3-4a06-8f59-a4d19ba2a7ed',
#               'instanceId': 334924735,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 5,
#               'trafficClass': 'MULTIMEDIA_STREAMING',
#               'displayName': '0'
#             },
#             {
#               'id': 'fb5f927a-e471-466b-a1da-6306ec8d1696',
#               'instanceId': 334924744,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 5,
#               'trafficClass': 'BROADCAST_VIDEO',
#               'displayName': '0'
#             },
#             {
#               'id': '5d96d295-2298-49ba-9cc2-2d3e9afe1bac',
#               'instanceId': 334924745,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'NETWORK_CONTROL',
#               'displayName': '0'
#             }
#           ],
#           'displayName': '0'
#         },
#         {
#           'id': '5978cfcb-4b2c-4ee3-89e6-bd2d017ec3df',
#           'instanceId': 334923598,
#           'instanceCreatedOn': 1732171051995,
#           'instanceUpdatedOn': 1732171051995,
#           'instanceVersion': 0,
#           'interfaceSpeed': 'TEN_GBPS',
#           'tcBandwidthSettings': [
#             {
#               'id': 'b806daf8-4a1f-44c6-b04f-60d34f3e7bb8',
#               'instanceId': 334924708,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'NETWORK_CONTROL',
#               'displayName': '0'
#             },
#             {
#               'id': '9c791c9e-6e06-4415-8f9b-3831a7c77b90',
#               'instanceId': 334924709,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 15,
#               'trafficClass': 'BEST_EFFORT',
#               'displayName': '0'
#             },
#             {
#               'id': 'c39de7ed-9dd5-4103-93a9-1a8c56ac86cd',
#               'instanceId': 334924706,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 35,
#               'trafficClass': 'VOIP_TELEPHONY',
#               'displayName': '0'
#             },
#             {
#               'id': 'dd4a20f7-ac75-4cf7-9a50-1ecc6b94f5a9',
#               'instanceId': 334924707,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 3,
#               'trafficClass': 'OPS_ADMIN_MGMT',
#               'displayName': '0'
#             },
#             {
#               'id': 'f40688a7-81b9-4105-9ebc-df4eb1166593',
#               'instanceId': 334924704,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 1,
#               'trafficClass': 'BROADCAST_VIDEO',
#               'displayName': '0'
#             },
#             {
#               'id': '8b6cc744-4667-49d2-a13c-82da81b7cb41',
#               'instanceId': 334924705,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 5,
#               'trafficClass': 'SIGNALING',
#               'displayName': '0'
#             },
#             {
#               'id': 'cfb9b6ce-a53f-4301-93e9-19c0d88b0425',
#               'instanceId': 334924702,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 7,
#               'trafficClass': 'TRANSACTIONAL_DATA',
#               'displayName': '0'
#             },
#             {
#               'id': '72afff08-7b34-4630-b801-52cac3e13e24',
#               'instanceId': 334924703,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 4,
#               'trafficClass': 'REAL_TIME_INTERACTIVE',
#               'displayName': '0'
#             },
#             {
#               'id': '6c10455e-95b7-4e32-9943-65c3445a40c5',
#               'instanceId': 334924700,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 1,
#               'trafficClass': 'MULTIMEDIA_STREAMING',
#               'displayName': '0'
#             },
#             {
#               'id': '336f2464-9454-42ef-92c4-d144234952be',
#               'instanceId': 334924701,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'SCAVENGER',
#               'displayName': '0'
#             },
#             {
#               'id': '172d28a6-a7b5-4c3a-86d3-937b276086bf',
#               'instanceId': 334924698,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 3,
#               'trafficClass': 'BULK_DATA',
#               'displayName': '0'
#             },
#             {
#               'id': '69df0cc9-b55d-406b-8318-77da0ae2ebdc',
#               'instanceId': 334924699,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 6,
#               'trafficClass': 'MULTIMEDIA_CONFERENCING',
#               'displayName': '0'
#             }
#           ],
#           'displayName': '0'
#         },
#         {
#           'id': '0f236075-d9e3-43aa-9673-14f91ebed68f',
#           'instanceId': 334923599,
#           'instanceCreatedOn': 1732171051995,
#           'instanceUpdatedOn': 1732171051995,
#           'instanceVersion': 0,
#           'interfaceSpeed': 'TEN_MBPS',
#           'tcBandwidthSettings': [
#             {
#               'id': '22e1cb6c-b006-408a-ad29-de9052035933',
#               'instanceId': 334924710,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'SCAVENGER',
#               'displayName': '0'
#             },
#             {
#               'id': '234748c4-1d07-4fb5-8eae-e50087e5151d',
#               'instanceId': 334924711,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 5,
#               'trafficClass': 'BROADCAST_VIDEO',
#               'displayName': '0'
#             },
#             {
#               'id': '3d91ec47-8b0d-4e08-bf58-1622e86682be',
#               'instanceId': 334924720,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'REAL_TIME_INTERACTIVE',
#               'displayName': '0'
#             },
#             {
#               'id': 'ad0b1ba4-b3b9-4d66-a7e5-a921bdb4a44f',
#               'instanceId': 334924721,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 15,
#               'trafficClass': 'BEST_EFFORT',
#               'displayName': '0'
#             },
#             {
#               'id': '9aa15e03-b31a-4168-9255-b305bc5933d1',
#               'instanceId': 334924718,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'VOIP_TELEPHONY',
#               'displayName': '0'
#             },
#             {
#               'id': '1de5382a-60e5-47a3-ae4a-6008e27f247f',
#               'instanceId': 334924719,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'MULTIMEDIA_CONFERENCING',
#               'displayName': '0'
#             },
#             {
#               'id': '6ed2190a-9b96-43b7-aeae-6a319d3dd5c1',
#               'instanceId': 334924716,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 5,
#               'trafficClass': 'BULK_DATA',
#               'displayName': '0'
#             },
#             {
#               'id': '702f623f-78d3-4c1a-9cb4-c9288eb68beb',
#               'instanceId': 334924717,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 5,
#               'trafficClass': 'SIGNALING',
#               'displayName': '0'
#             },
#             {
#               'id': '9a875d44-334e-417d-ab03-748f85d14c3b',
#               'instanceId': 334924714,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'NETWORK_CONTROL',
#               'displayName': '0'
#             },
#             {
#               'id': 'e303208f-d316-40dc-9961-70111a8ef04e',
#               'instanceId': 334924715,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 5,
#               'trafficClass': 'OPS_ADMIN_MGMT',
#               'displayName': '0'
#             },
#             {
#               'id': 'bc332635-ae26-4dfe-ae90-7e442bc87c84',
#               'instanceId': 334924712,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 10,
#               'trafficClass': 'TRANSACTIONAL_DATA',
#               'displayName': '0'
#             },
#             {
#               'id': 'f347c377-7246-474f-be2a-7143cb4b573d',
#               'instanceId': 334924713,
#               'instanceCreatedOn': 1732171051995,
#               'instanceUpdatedOn': 1732171051995,
#               'instanceVersion': 0,
#               'bandwidthPercentage': 5,
#               'trafficClass': 'MULTIMEDIA_STREAMING',
#               'displayName': '0'
#             }
#           ],
#           'displayName': '0'
#         }
#       ],
#       'displayName': '0'
#     },
#     {
#       'id': '5e2395b7-5f08-4557-afdc-e39365125d01',
#       'instanceId': 330985843,
#       'instanceCreatedOn': 1732164727952,
#       'instanceUpdatedOn': 1732164727952,
#       'instanceVersion': 1,
#       'priority': 1,
#       'type': 'DSCP_CUSTOMIZATION',
#       'tcDscpSettings': [
#         {
#           'id': '01f3913a-a1bb-47a4-8fa4-14757ab2c2fb',
#           'instanceId': 330986718,
#           'instanceCreatedOn': 1732164727952,
#           'instanceUpdatedOn': 1732164727952,
#           'instanceVersion': 1,
#           'dscp': '48',
#           'trafficClass': 'NETWORK_CONTROL',
#           'displayName': '0'
#         },
#         {
#           'id': 'dd0e0de7-a68a-4919-b566-399b047eaaf5',
#           'instanceId': 330986719,
#           'instanceCreatedOn': 1732164727952,
#           'instanceUpdatedOn': 1732164727952,
#           'instanceVersion': 1,
#           'dscp': '45',
#           'trafficClass': 'REAL_TIME_INTERACTIVE',
#           'displayName': '0'
#         },
#         {
#           'id': '872b2bb6-d579-490d-b78f-b120a3cf264b',
#           'instanceId': 330986716,
#           'instanceCreatedOn': 1732164727952,
#           'instanceUpdatedOn': 1732164727952,
#           'instanceVersion': 1,
#           'dscp': '40',
#           'trafficClass': 'VOIP_TELEPHONY',
#           'displayName': '0'
#         },
#         {
#           'id': 'be0ec6e4-f668-4122-bb8a-0cb25a47bd50',
#           'instanceId': 330986717,
#           'instanceCreatedOn': 1732164727952,
#           'instanceUpdatedOn': 1732164727952,
#           'instanceVersion': 1,
#           'dscp': '44',
#           'trafficClass': 'BROADCAST_VIDEO',
#           'displayName': '0'
#         },
#         {
#           'id': '36cad2d1-ec43-489f-9116-6c08b777849b',
#           'instanceId': 330986722,
#           'instanceCreatedOn': 1732164727952,
#           'instanceUpdatedOn': 1732164727952,
#           'instanceVersion': 1,
#           'dscp': '34',
#           'trafficClass': 'MULTIMEDIA_CONFERENCING',
#           'displayName': '0'
#         },
#         {
#           'id': 'd46ace00-21a8-4a40-9c18-4df01063227e',
#           'instanceId': 330986723,
#           'instanceCreatedOn': 1732164727952,
#           'instanceUpdatedOn': 1732164727952,
#           'instanceVersion': 1,
#           'dscp': '24',
#           'trafficClass': 'SIGNALING',
#           'displayName': '0'
#         },
#         {
#           'id': '2520bcf2-009d-47c7-98c8-6ecb6797a44c',
#           'instanceId': 330986720,
#           'instanceCreatedOn': 1732164727952,
#           'instanceUpdatedOn': 1732164727952,
#           'instanceVersion': 1,
#           'dscp': '0',
#           'trafficClass': 'BEST_EFFORT',
#           'displayName': '0'
#         },
#         {
#           'id': '59077f0d-ebfb-4f79-b680-c8ed23e3adcd',
#           'instanceId': 330986721,
#           'instanceCreatedOn': 1732164727952,
#           'instanceUpdatedOn': 1732164727952,
#           'instanceVersion': 1,
#           'dscp': '36',
#           'trafficClass': 'MULTIMEDIA_STREAMING',
#           'displayName': '0'
#         },
#         {
#           'id': '436b4e09-396a-4cbd-9d12-afcd2b855bce',
#           'instanceId': 330986726,
#           'instanceCreatedOn': 1732164727952,
#           'instanceUpdatedOn': 1732164727952,
#           'instanceVersion': 1,
#           'dscp': '8',
#           'trafficClass': 'SCAVENGER',
#           'displayName': '0'
#         },
#         {
#           'id': '42cab192-5565-4998-84a5-a2ec6e41d8b3',
#           'instanceId': 330986727,
#           'instanceCreatedOn': 1732164727952,
#           'instanceUpdatedOn': 1732164727952,
#           'instanceVersion': 1,
#           'dscp': '16',
#           'trafficClass': 'TRANSACTIONAL_DATA',
#           'displayName': '0'
#         },
#         {
#           'id': '04363f64-de5b-425c-b55c-2cfcf6d42270',
#           'instanceId': 330986724,
#           'instanceCreatedOn': 1732164727952,
#           'instanceUpdatedOn': 1732164727952,
#           'instanceVersion': 1,
#           'dscp': '32',
#           'trafficClass': 'OPS_ADMIN_MGMT',
#           'displayName': '0'
#         },
#         {
#           'id': '52dff2f3-d3aa-4f2f-8a7d-e119585325e7',
#           'instanceId': 330986725,
#           'instanceCreatedOn': 1732164727952,
#           'instanceUpdatedOn': 1732164727952,
#           'instanceVersion': 1,
#           'dscp': '10',
#           'trafficClass': 'BULK_DATA',
#           'displayName': '0'
#         }
#           ],
#           'displayName': '0'
#         }
#       ],
#       'contractClassifier': [
        
#       ],
#       'displayName': '0'
#     }
#   ],
#   'queuing_profile_exists': True
# }

required_details = required_queuing_profile_details['application_queuing_details'][0]

want_bandwidth_settings = {
    key.upper(): value for key, value in required_details['bandwidth_settings']['bandwidth_percentages'].items()
}

want_dscp_settings = {key.upper(): value.upper() if isinstance(value, str) else value
                      for key, value in required_details['dscp_settings'].items()}


# Current queuing profile bandwidth and DSCP settings
have_bandwidth_settings = {
    tc['trafficClass']: tc['bandwidthPercentage']
    for tc in queuing_profile['current_queuing_profile'][0]['clause'][0]['interfaceSpeedBandwidthClauses'][0]['tcBandwidthSettings']
}

have_dscp_settings = {
    tc['trafficClass']: tc['dscp']
    for tc in queuing_profile['current_queuing_profile'][0]['clause'][1]['tcDscpSettings']
}

# Output the extracted data
print("want Bandwidth Settings:")
print(want_bandwidth_settings)

print("\nhave Bandwidth Settings:")
print(have_bandwidth_settings)

print("\nwant DSCP Settings:")
print(want_dscp_settings)

print("\nhave DSCP Settings:")
print(have_dscp_settings)

# Initialize final dictionary
final_want_bandwidth_dict = {}

for traffic_class, want_value in want_bandwidth_settings.items():
    # Convert want_value to int for comparison
    want_value = int(want_value)

    if traffic_class in have_bandwidth_settings:
        have_value = have_bandwidth_settings[traffic_class]
        # Compare values
        if want_value == have_value:
            final_want_bandwidth_dict[traffic_class] = have_value
        else:
            final_want_bandwidth_dict[traffic_class] = want_value
    else:
        # If the traffic class is only in want
        final_want_bandwidth_dict[traffic_class] = want_value

print("Final Want bandwidth Dict:")
print(final_want_bandwidth_dict)

final_want_dscp_dict = {}
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
print("Final Want dscp Dict:")
print(final_want_dscp_dict)

id_bandwidth_mapping = {}
id_dscp_mapping = {}

# Navigate through the queuing profile structure
current_profiles = queuing_profile.get('current_queuing_profile', [])

for profile in current_profiles:
    for clause in profile.get('clause', []):
        if clause.get('type') == 'BANDWIDTH':
            for interface_clause in clause.get('interfaceSpeedBandwidthClauses', []):
                for bandwidth_setting in interface_clause.get('tcBandwidthSettings', []):
                    traffic_class = bandwidth_setting.get('trafficClass')
                    instance_id = bandwidth_setting.get('instanceId')
                    if traffic_class and instance_id:
                        id_bandwidth_mapping[traffic_class] = instance_id
        elif clause.get('type') == 'DSCP_CUSTOMIZATION':
            for dscp_setting in clause.get('tcDscpSettings', []):
                dscp = dscp_setting.get('dscp')
                traffic_class = dscp_setting.get('trafficClass')
                instance_id = dscp_setting.get('instanceId')
                if dscp and traffic_class and instance_id:
                    id_dscp_mapping[traffic_class] =  instance_id

print("Bandwidth Mapping:", id_bandwidth_mapping)
print("DSCP Mapping:", id_dscp_mapping)


update_required = False

# Checking Bandwidth settings
for key, value in final_want_bandwidth_dict.items():
    if key in have_bandwidth_settings:
        if have_bandwidth_settings[key] != value:
            print(f"Update Required: Key '{key}' has value '{value}' in Final Want Bandwidth Dict and '{have_bandwidth_settings[key]}' in Bandwidth Settings.")
            update_required = True
    else:
        print(f"Update Required: Key '{key}' is missing in Bandwidth Settings.")
        update_required = True

# Checking DSCP settings
for key, value in final_want_dscp_dict.items():
    if key in have_dscp_settings:
        if int(have_dscp_settings[key]) != value:
            print(f"Update Required: Key '{key}' has value '{value}' in Final Want DSCP Dict and '{have_dscp_settings[key]}' in DSCP Settings.")
            update_required = True
    else:
        print(f"Update Required: Key '{key}' is missing in DSCP Settings.")
        update_required = True

if not update_required:
    print("No updates required. Both dictionaries match.")
else:
    print("Update required.")

instance_ids = {}
for clause in queuing_profile['current_queuing_profile'][0]['clause']:
    if clause['type'] == 'BANDWIDTH':
        instance_ids['bandwidth'] = clause['instanceId']
    elif clause['type'] == 'DSCP_CUSTOMIZATION':
        instance_ids['dscp'] = clause['instanceId']

interface_speed_clause = queuing_profile['current_queuing_profile'][0]['clause'][0]['interfaceSpeedBandwidthClauses'][0]
if interface_speed_clause['interfaceSpeed'] == 'ALL':
    interface_speed_all_instance_id = interface_speed_clause['instanceId']
# Construct the payload
payload = [
    {
        "id": queuing_profile['current_queuing_profile'][0].get("id"),
        "name": queuing_profile['current_queuing_profile'][0].get("name"),
        "description": "This is a sample test description",
        "clause": [
            {
                "instanceId": instance_ids.get('bandwidth'),
                "type": "BANDWIDTH",
                "isCommonBetweenAllInterfaceSpeeds": True,
                "interfaceSpeedBandwidthClauses": [
                    {
                        "instanceId": interface_speed_all_instance_id,
                        "interfaceSpeed": "ALL",
                        "tcBandwidthSettings": [
                            {
                                "instanceId": id_bandwidth_mapping[traffic_class],
                                "trafficClass": traffic_class,
                                "bandwidthPercentage": final_want_bandwidth_dict[traffic_class]
                            }
                            for traffic_class in final_want_bandwidth_dict
                        ]
                    }
                ]
            },
            {
                "instanceId": instance_ids.get('dscp'),
                "type": "DSCP_CUSTOMIZATION",
                "tcDscpSettings": [
                    {
                        "instanceId": id_dscp_mapping[traffic_class],
                        "trafficClass": traffic_class,
                        "dscp": final_want_dscp_dict[traffic_class]
                    }
                    for traffic_class in final_want_dscp_dict
                ]
            }
        ]
    }
]

# Printing out the payload to check the result
import json
print(json.dumps(payload, indent=2))





























































# existing_bandwidth_settings = {}
# existing_dscp_settings = {}

# new_bandwidth_settings = {}
# new_dscp_settings = {}


# # Extract the details from required_queuing_profile_details
# queuing_profile_details = required_queuing_profile_details["application_queuing_details"]

# for profile in queuing_profile_details:
#     if "bandwidth_settings" in profile:
#         for traffic_class, bandwidth_percentage in profile["bandwidth_settings"]["bandwidth_percentages"].items():
#             new_bandwidth_settings[traffic_class.upper()] = {  # Ensure traffic class is upper case
#                 "bandwidthPercentage": bandwidth_percentage
#             }

#     if "dscp_settings" in profile:
#         for traffic_class, dscp_value in profile["dscp_settings"].items():
#             new_dscp_settings[traffic_class.upper()] = {  # Ensure traffic class is upper case
#                 "dscp": dscp_value
#             }

# # Compare and update existing bandwidth settings if any changes
# updated_bandwidth_settings = False
# for traffic_class, new_bandwidth in new_bandwidth_settings.items():
#     if traffic_class not in existing_bandwidth_settings or existing_bandwidth_settings[traffic_class]["bandwidthPercentage"] != new_bandwidth["bandwidthPercentage"]:
#         # Update the bandwidth settings and retain the instanceId from the existing settings
#         existing_bandwidth_settings[traffic_class] = {
#             "bandwidthPercentage": new_bandwidth["bandwidthPercentage"],
#             "instanceId": existing_bandwidth_settings.get(traffic_class, {}).get("instanceId", None)
#         }
#         updated_bandwidth_settings = True

# # DSCP settings comparison (no update needed in this case based on your expected output)
# updated_dscp_settings = False
# for traffic_class, new_dscp in new_dscp_settings.items():
#     if traffic_class not in existing_dscp_settings or existing_dscp_settings[traffic_class]["dscp"] != new_dscp["dscp"]:
#         # Update the DSCP settings and retain the instanceId from the existing settings
#         existing_dscp_settings[traffic_class] = {
#             "dscp": new_dscp["dscp"],
#             "instanceId": existing_dscp_settings.get(traffic_class, {}).get("instanceId", None)
#         }
#         updated_dscp_settings = True

# # Output the updated dictionaries
# if updated_bandwidth_settings:
#     print("Updated Bandwidth Settings:", existing_bandwidth_settings)
# else:
#     print("No changes to Bandwidth Settings.")

# if updated_dscp_settings:
#     print("Updated DSCP Settings:", existing_dscp_settings)
# else:
#     print("No changes to DSCP Settings.")


# # output :
# # Existing Bandwidth Settings: {'BROADCAST_VIDEO': {'bandwidthPercentage': 2, 'instanceId': 334925542}, 'NETWORK_CONTROL': {'bandwidthPercentage': 3, 'instanceId': 334925543}, 'MULTIMEDIA_CONFERENCING': {'bandwidthPercentage': 10, 'instanceId': 334925540}, 'SIGNALING': {'bandwidthPercentage': 10, 'instanceId': 334925541}, 'TRANSACTIONAL_DATA': {'bandwidthPercentage': 10, 'instanceId': 334925538}, 'BULK_DATA': {'bandwidthPercentage': 5, 'instanceId': 334925539}, 'REAL_TIME_INTERACTIVE': {'bandwidthPercentage': 20, 'instanceId': 334925548}, 'MULTIMEDIA_STREAMING': {'bandwidthPercentage': 11, 'instanceId': 334925549}, 'SCAVENGER': {'bandwidthPercentage': 5, 'instanceId': 334925546}, 'VOIP_TELEPHONY': {'bandwidthPercentage': 15, 'instanceId': 334925547}, 'BEST_EFFORT': {'bandwidthPercentage': 10, 'instanceId': 334925544}, 'OPS_ADMIN_MGMT': {'bandwidthPercentage': 5, 'instanceId': 334925545}}
# # Existing DSCP Settings: {'SIGNALING': {'dscp': '4', 'instanceId': 330986874}, 'NETWORK_CONTROL': {'dscp': '48', 'instanceId': 330986875}, 'MULTIMEDIA_STREAMING': {'dscp': '27', 'instanceId': 330986872}, 'OPS_ADMIN_MGMT': {'dscp': '23', 'instanceId': 330986873}, 'TRANSACTIONAL_DATA': {'dscp': '28', 'instanceId': 330986878}, 'BULK_DATA': {'dscp': '10', 'instanceId': 330986879}, 'MULTIMEDIA_CONFERENCING': {'dscp': '20', 'instanceId': 330986876}, 'VOIP_TELEPHONY': {'dscp': '45', 'instanceId': 330986877}, 'REAL_TIME_INTERACTIVE': {'dscp': '34', 'instanceId': 330986882}, 'BEST_EFFORT': {'dscp': '0', 'instanceId': 330986883}, 'SCAVENGER': {'dscp': '2', 'instanceId': 330986880}, 'BROADCAST_VIDEO': {'dscp': '46', 'instanceId': 330986881}}
# # New Bandwidth Settings: {'transactional_data': {'bandwidthPercentage': '11'}, 'best_effort': {'bandwidthPercentage': '10'}, 'voip_telephony': {'bandwidthPercentage': '15'}, 'multimedia_streaming': {'bandwidthPercentage': '11'}, 'real_time_interactive': {'bandwidthPercentage': '20'}, 'multimedia_conferencing': {'bandwidthPercentage': '10'}, 'signaling': {'bandwidthPercentage': '10'}, 'scavenger': {'bandwidthPercentage': '5'}, 'ops_admin_mgmt': {'bandwidthPercentage': '5'}, 'broadcast_video': {'bandwidthPercentage': '2'}, 'network_control': {'bandwidthPercentage': '3'}, 'bulk_data': {'bandwidthPercentage': '5'}}
# # New DSCP Settings: {'multimedia_conferencing': {'dscp': '20'}, 'ops_admin_mgmt': {'dscp': '23'}, 'transactional_data': {'dscp': '28'}, 'voip_telephony': {'dscp': '45'}, 'multimedia_streaming': {'dscp': '27'}, 'broadcast_video': {'dscp': '46'}, 'network_control': {'dscp': '48'}, 'best_effort': {'dscp': '0'}, 'signaling': {'dscp': '4'}, 'bulk_data': {'dscp': '10'}, 'scavenger': {'dscp': '2'}, 'real_time_interactive': {'dscp': '34'}}

# # expected output:
# # updated Bandwidth Settings: {'BROADCAST_VIDEO': {'bandwidthPercentage': 2, 'instanceId': 334925542}, 'NETWORK_CONTROL': {'bandwidthPercentage': 3, 'instanceId': 334925543}, 'MULTIMEDIA_CONFERENCING': {'bandwidthPercentage': 10, 'instanceId': 334925540}, 'SIGNALING': {'bandwidthPercentage': 10, 'instanceId': 334925541}, 'TRANSACTIONAL_DATA': {'bandwidthPercentage': 11, 'instanceId': 334925538}, 'BULK_DATA': {'bandwidthPercentage': 5, 'instanceId': 334925539}, 'REAL_TIME_INTERACTIVE': {'bandwidthPercentage': 20, 'instanceId': 334925548}, 'MULTIMEDIA_STREAMING': {'bandwidthPercentage': 11, 'instanceId': 334925549}, 'SCAVENGER': {'bandwidthPercentage': 5, 'instanceId': 334925546}, 'VOIP_TELEPHONY': {'bandwidthPercentage': 15, 'instanceId': 334925547}, 'BEST_EFFORT': {'bandwidthPercentage': 10, 'instanceId': 334925544}, 'OPS_ADMIN_MGMT': {'bandwidthPercentage': 5, 'instanceId': 334925545}}
# # updated DSCP Settings: {'SIGNALING': {'dscp': '4', 'instanceId': 330986874}, 'NETWORK_CONTROL': {'dscp': '48', 'instanceId': 330986875}, 'MULTIMEDIA_STREAMING': {'dscp': '27', 'instanceId': 330986872}, 'OPS_ADMIN_MGMT': {'dscp': '23', 'instanceId': 330986873}, 'TRANSACTIONAL_DATA': {'dscp': '28', 'instanceId': 330986878}, 'BULK_DATA': {'dscp': '10', 'instanceId': 330986879}, 'MULTIMEDIA_CONFERENCING': {'dscp': '20', 'instanceId': 330986876}, 'VOIP_TELEPHONY': {'dscp': '45', 'instanceId': 330986877}, 'REAL_TIME_INTERACTIVE': {'dscp': '34', 'instanceId': 330986882}, 'BEST_EFFORT': {'dscp': '0', 'instanceId': 330986883}, 'SCAVENGER': {'dscp': '2', 'instanceId': 330986880}, 'BROADCAST_VIDEO': {'dscp': '46', 'instanceId': 330986881}}

# # as there is some changes between Existing Bandwidth Settings and New Bandwidth Settings but no update is required so using the Existing DSCP Settings

# # Initialize dictionaries to store new bandwidth and DSCP settings

# # Initialize existing and new settings
# existing_bandwidth_settings = {

# }

# existing_dscp_settings = {

# }

# new_bandwidth_settings = {}
# new_dscp_settings = {}

# # Extract new settings from `required_queuing_profile_details`
# queuing_profile_details = required_queuing_profile_details["application_queuing_details"]

# for profile in queuing_profile_details:
#     if "bandwidth_settings" in profile:
#         for traffic_class, bandwidth_percentage in profile["bandwidth_settings"]["bandwidth_percentages"].items():
#             new_bandwidth_settings[traffic_class.upper()] = {
#                 "bandwidthPercentage": int(bandwidth_percentage)
#             }

#     if "dscp_settings" in profile:
#         for traffic_class, dscp_value in profile["dscp_settings"].items():
#             new_dscp_settings[traffic_class.upper()] = {
#                 "dscp": int(dscp_value)
#             }

# # Update existing bandwidth settings
# updated_bandwidth_settings = False
# for traffic_class, new_bandwidth in new_bandwidth_settings.items():
#     if (
#         traffic_class not in existing_bandwidth_settings or 
#         existing_bandwidth_settings[traffic_class]["bandwidthPercentage"] != new_bandwidth["bandwidthPercentage"]
#     ):
#         # Update with new bandwidth percentage, retain instanceId if exists
#         existing_bandwidth_settings[traffic_class] = {
#             "bandwidthPercentage": new_bandwidth["bandwidthPercentage"],
#             "instanceId": existing_bandwidth_settings.get(traffic_class, {}).get("instanceId", None),
#         }
#         updated_bandwidth_settings = True

# # Update existing DSCP settings
# updated_dscp_settings = False
# for traffic_class, new_dscp in new_dscp_settings.items():
#     if (
#         traffic_class not in existing_dscp_settings or 
#         existing_dscp_settings[traffic_class]["dscp"] != new_dscp["dscp"]
#     ):
#         # Update with new DSCP value, retain instanceId if exists
#         existing_dscp_settings[traffic_class] = {
#             "dscp": new_dscp["dscp"],
#             "instanceId": existing_dscp_settings.get(traffic_class, {}).get("instanceId", None),
#         }
#         updated_dscp_settings = True

# # Print final settings and flags for updates
# print("Updated Bandwidth Settings:", updated_bandwidth_settings)
# print("Updated DSCP Settings:", updated_dscp_settings)
# print("Final Bandwidth Settings:", existing_bandwidth_settings)
# print("Final DSCP Settings:", existing_dscp_settings)
