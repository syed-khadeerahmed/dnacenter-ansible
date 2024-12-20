site_id = "111111111111111111"
queuing_profile_id = "22222222222222"
application_policy_name = "sample"
business_relevant_set_id = [{'name': 'email', 'id': '5b428b73-00e6-4f3a-8d6c-2cbf5eb8981a'}] 
business_irrelevant_set_id = [{'name': 'file-sharing', 'id': '0339555a-974a-4f54-9c4a-82da248a3673'}] 
default_set_id = [{'name': 'collaboration-apps', 'id': '7c6ea543-dddc-4e45-b490-1d3a1630f7ef'}]
application_queuing_profile_name = "asampleq5"
new_application_policy_details = {'application_policy_name': 'sample_application_policy', 'policy_status': 'deployed', 'site_name': 'global/Chennai/LTTS/FLOOR1', 'device_type': 'wired', 'application_queuing_profile_name': 'Asampleq5', 'clause': [{'clause_type': '“BUSINESS_RELEVANCE"', 'relevance_details': [{'relevance': 'BUSINESS_RELEVANT', 'application_set_name': ['email']}, {'relevance': 'BUSINESS_IRRELEVANT', 'application_set_name': ['file-sharing']}, {'relevance': 'DEFAULT', 'application_set_name': ['collaboration-apps']}]}]} 

# Determine the deletePolicyStatus
policy_status = new_application_policy_details.get("policy_status")
delete_policy_status = {
    "deployed": "NONE",
    "deleted": "DELETED",
    "restored": "RESTORED"
}.get(policy_status, "NONE")

# Map relevance to application set IDs
relevance_map = {
    "BUSINESS_RELEVANT": business_relevant_set_id,
    "BUSINESS_IRRELEVANT": business_irrelevant_set_id,
    "DEFAULT": default_set_id
}

# Generate payload
payload = []
# for queuing profile
payload.append({
            "name": f"{application_policy_name}_{application_queuing_profile_name}",
            "deletePolicyStatus": delete_policy_status,
            "policyScope": f"{application_policy_name}",
            "priority": "100",
            "advancedPolicyScope": {
                "name": f"{application_policy_name}",
                "advancedPolicyScopeElement": [
                    {
                        "groupId": [
                            site_id
                        ],
                        "ssid": []
                    }
                ]
            },
            "contract": {
                "idRef": queuing_profile_id
            }
        },
)

for relevance_detail in new_application_policy_details['clause'][0]['relevance_details']:
    relevance_level = relevance_detail['relevance']
    application_set_names = relevance_detail['application_set_name']
    
    for app_set_name in application_set_names:
        # Find the matching application set ID
        matching_set = next((item for item in relevance_map[relevance_level] if item['name'] == app_set_name), None)
        if not matching_set:
            continue
        
        # Append the policy details to the payload
        payload.append({
            "name": f"{application_policy_name}_{app_set_name}",
            "deletePolicyStatus": delete_policy_status,
            "policyScope": f"{application_policy_name}",
            "priority": "100",
            "advancedPolicyScope": {
                "name": f"{application_policy_name}",
                "advancedPolicyScopeElement": [
                    {
                        "groupId": [site_id],
                        "ssid": []
                    }
                ]
            },
            "exclusiveContract": {
                "clause": [
                    {
                        "type": "BUSINESS_RELEVANCE",
                        "relevanceLevel": relevance_level
                    }
                ]
            },
            "producer": {
                "scalableGroup": [
                    {
                        "idRef": matching_set['id']
                    }
                ]
            }
        })



# Print the payload
import json
print(json.dumps(payload, indent=4))
