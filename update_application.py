application_set_name = [{'clause_type': '“BUSINESS_RELEVANCE"', 'relevance_details': [{'relevance': 'BUSINESS_RELEVANT', 'application_set_name': ['sample_application_set', 'sample_application_set', 'sample_application_set', 'sample_application_set']}, {'relevance': 'BUSINESS_IRRELEVANT', 'application_set_name': ['sample_application_set', 'sample_application_set', 'sample_application_set', 'sample_application_set']}, {'relevance': 'DEFAULT', 'application_set_name': ['sample_application_set', 'sample_application_set', 'sample_application_set', 'sample_application_set']}]}]

# Initialize empty lists for each relevance
business_relevant = []
business_irrelevant = []
default = []

# Populate the lists based on relevance
for item in application_set_name:
    for relevance in item['relevance_details']:
        if relevance['relevance'] == 'BUSINESS_RELEVANT':
            business_relevant.extend(relevance['application_set_name'])
        elif relevance['relevance'] == 'BUSINESS_IRRELEVANT':
            business_irrelevant.extend(relevance['application_set_name'])
        elif relevance['relevance'] == 'DEFAULT':
            default.extend(relevance['application_set_name'])

# Print the results
print("Business Relevant:", business_relevant)
print("Business Irrelevant:", business_irrelevant)
print("Default:", default)