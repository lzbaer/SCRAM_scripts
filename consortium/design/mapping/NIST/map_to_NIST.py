
import json
from collections import OrderedDict
import csv

def main():
	with open("nist_800_53-rev5_attack-14.1-enterprise_json.json", "r") as f:
		mappings = json.load(f)
		mappings = mappings["mapping_objects"]

	with open("../aggregate_all.json", "r") as f:
		techniques = json.load(f)
		techniques = techniques["Techniques"]

	controls = {}
	for mapping in mappings:
		if mapping["attack_object_name"] in techniques and mapping["capability_id"] != None:
			if mapping["capability_id"] not in controls:
				controls[mapping["capability_id"]] = {
				"capability_group": mapping["capability_group"],
				"capability_description": mapping["capability_description"],
				"techniques": {},
				"count": 0,
				}

			controls[mapping["capability_id"]]["techniques"][mapping["attack_object_name"]] = mapping["mapping_type"]
			controls[mapping["capability_id"]]["count"] += techniques[mapping["attack_object_name"]]["count"]

	# truncate
	sortd = OrderedDict(sorted(controls.items(), key=lambda item: item[1]['count'], reverse=True))

	# with open("control_counts.json", "w") as f:
	# 	json.dump(sortd, f, indent=4)

	with open('control_counts.csv', 'w') as output:
	    writer = csv.writer(output)
	    for key, value in sortd.items():
	        writer.writerow([key, value["capability_group"], value["capability_description"], value["count"]])


if __name__ == "__main__":
    main()

