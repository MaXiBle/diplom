import json

# Load the JSON data
with open('output_results.json', 'r', encoding='utf-8') as file_results:
    output_results = json.load(file_results)

with open('output.json', 'r', encoding='utf-8') as file_output:
    output = json.load(file_output)

# Create a dictionary from output_results.json with Entry_ID as the key
results_dict = {entry['Entry_ID']: entry for entry in output_results}

# Update output.json with the relevant data from output_results.json
for entry in output:
    for mapping in entry.get("Taxonomy_Mappings", []):
        entry_id = mapping.get("Entry_ID")
        if entry_id and entry_id in results_dict:
            # Find the INFO array and insert data before "CAPEC_ID"
            info_list = mapping.get("INFO", [])
            for info in info_list:
                # Insert all fields from results_dict[entry_id] before "CAPEC_ID"
                updated_info = {**results_dict[entry_id], **info}
                info.clear()
                info.update(updated_info)

# Save the updated output.json
with open('updated_output.json', 'w', encoding='utf-8') as updated_file:
    json.dump(output, updated_file, indent=4, ensure_ascii=False)
