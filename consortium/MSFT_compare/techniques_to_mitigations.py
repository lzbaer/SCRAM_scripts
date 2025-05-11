import argparse
import json
from collections import OrderedDict
from itertools import islice

from mitreattack.stix20 import MitreAttackData

def main(argv=None):
	"""Entrypoint for layerExporter_cli."""
	parser = argparse.ArgumentParser(description="ATT&CK Techniques to Mitigations")

	parser.add_argument(
        "-s",
        "--source",
        choices=["taxii", "local", "remote"],
        default="taxii",
        help="What source to utilize when building the matrix",
    )

	parser.add_argument(
		"--resource",
		help="Path to the local resource if --source=local, or url of an ATT&CK Workbench"
		" instance if --source=remote",
		default=None,
	)
	# parser.add_argument("-o", "--output", nargs="+", help="Path(s) to the aggregated json file", required=True)

	args = parser.parse_args(args=argv)

	with open("train_tec_count.json", "r") as f:
		train_data = json.load(f)

	with open("test_tec_count.json", "r") as f:
		test_data = json.load(f)

	if args.source == "local":
		mitre_attack_data = MitreAttackData(args.resource)
	else:
		mitre_attack_data = MitreAttackData("attack-stix-data/enterprise-attack/enterprise-attack.json")

	t_lookup = mitre_attack_data.get_techniques(remove_revoked_deprecated=True)
	t_lookup = dict([(t["name"],t) for t in t_lookup]) # eventually want to update with external id, ala t.get("external_references")

	for (label, data) in [("train", train_data), ("test", test_data)]:
		mit_count = {}
		for tid, tech in data.items():
			mitigations = mitre_attack_data.get_mitigations_mitigating_technique(t_lookup[tech["name"]].id)
			# print(tech["name"], t_lookup[tech["name"]].id, mitigations)
			for m in mitigations:
				key = m["object"].name
				if key not in mit_count:
					mit_count[key] = {"id": m["object"].external_references[0].external_id, "description": m["object"].description, "techniques": [tech["name"]], "count": tech["count"]}
				else:
					mit_count[key]["techniques"].append(tech["name"])
					mit_count[key]["count"] += tech["count"]

		sortd = OrderedDict(sorted(mit_count.items(), key=lambda item: item[1]['count'], reverse=True))
		mit_count = sortd
		with open(f"{label}_mit_count.json", "w") as f:
			json.dump(mit_count, f, indent=4)
		
		TOP = 15
		sortd = OrderedDict(islice(mit_count.items(), TOP))
		mit_count = sortd
		with open(f"{label}_mit_count_top.json", "w") as f:
			json.dump(mit_count, f, indent=4)


if __name__ == "__main__":
	main()


"""
example run:
python techniques_to_mitigations.py -s local --resource ../../collections/enterprise.json
"""
