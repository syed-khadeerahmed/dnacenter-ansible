# Define the sets
want_business_relevant_set_name = ['email' ]
want_business_irrelevant_set_name = ['file-sharing']
want_default_set_name = ['collaboration-apps']

have_business_relevant_set_name = ['file-sharing']
have_business_irrelevant_set_name = ['email']
have_default_set_name = ['collaboration-apps']

# Define final lists to store the differences
final_business_relevant_set_name = []
final_business_irrelevant_set_name = []
final_default_set_name = []

# List of all want and have lists
want_lists = [
    (want_business_relevant_set_name, have_business_relevant_set_name, final_business_relevant_set_name),
    (want_business_irrelevant_set_name, have_business_irrelevant_set_name, final_business_irrelevant_set_name),
    (want_default_set_name, have_default_set_name, final_default_set_name)
]

# Compare and append missing elements to the final lists
for want_item, have_item, final_item in want_lists:
    for w in want_item:
        if w not in have_item:
            final_item.append(w)  # Add missing item from "want"
    if not want_item:  # If the "want" list is empty, ensure "have" is added to final
        final_item.extend([item for item in have_item if item not in final_item])

# Ensure the default list is empty if no relevant/default values are there
if not want_default_set_name:
    final_default_set_name = []
if not want_business_relevant_set_name:
    final_business_relevant_set_name = []
if not want_business_irrelevant_set_name:
    final_business_irrelevant_set_name = []

# Print the final lists
print("Final Business Relevant:", final_business_relevant_set_name)
print("Final Business Irrelevant:", final_business_irrelevant_set_name)
print("Final Default:", final_default_set_name)
