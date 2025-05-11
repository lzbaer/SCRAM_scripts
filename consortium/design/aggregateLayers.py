"""Adaptation of `layerExporter_cli.py` script from `mitreattack-python`.

Link: https://github.com/mitre-attack/mitreattack-python/blob/master/mitreattack/navlayers/layerExporter_cli.py
"""

import argparse
import os
import json
from copy import deepcopy
import tempfile
from collections import OrderedDict
from operator import itemgetter

from mitreattack.navlayers.exporters.to_svg import ToSvg, SVGConfig
from mitreattack.navlayers.exporters.to_excel import ToExcel
from mitreattack.navlayers.core import Layer

from mitreattack.stix20 import MitreAttackData

def get_name(codex, id):
    """Do lookups to retrieve the name of a technique given it's ID.

    :param codex: The list of lists matrix object (output of get_matrix)
    :param id: The ID of the technique to retrieve the name of
    :return: The name of the technique referenced by id
    """
    for col in codex:
        tac = col.tactic.name
        if col.tactic.id == id:
            return (tac, col.tactic.name)
        for entry in col.subtechniques:
            for subtech in col.subtechniques[entry]:
                if subtech.id == id:
                    return (tac, subtech.name)
        for entry in col.techniques:
            if entry.id == id:
                return (tac, entry.name)
    return ("", "")

def get_mitigations(toExcel, layerInit, merged_mits, filename, filepath="layer.xlsx", source="local", resource="collections/enterprise.json"):
    if not isinstance(layerInit, Layer):
        raise TypeError

    layer = deepcopy(layerInit)

    if toExcel.domain not in layer.layer.domain:
        raise ValueError(f"layer domain ({layer.layer.domain}) does not match exporter domain ({toExcel.domain})")

    included_subs = []
    if layer.layer.techniques:
        for entry in layer.layer.techniques:
            if entry.showSubtechniques:
                if entry.tactic:
                    included_subs.append((entry.techniqueID, entry.tactic))
                else:
                    included_subs.append((entry.techniqueID, False))

    excluded = []
    if layer.layer.hideDisabled:
        for entry in layer.layer.techniques:
            if entry.enabled is False:
                if entry.tactic:
                    excluded.append((entry.techniqueID, entry.tactic))
                else:
                    excluded.append((entry.techniqueID, False))
    
    codex = toExcel.raw_handle.h.get_matrix()
    techs = [t for (t, _) in included_subs ]
    if source == "local":
        mitre_attack_data = MitreAttackData(resource)
    else:
        mitre_attack_data = MitreAttackData("attack-stix-data/enterprise-attack/enterprise-attack.json")

    t_lookup = mitre_attack_data.get_techniques(remove_revoked_deprecated=True)
    t_lookup = dict([(t["name"],t) for t in t_lookup]) # eventually want to update with external id, ala t.get("external_references")
    output = dict()
    for tech in techs:
        (tactic, name) = get_name(codex, tech)
        if name not in t_lookup.keys():
            raise Exception("Missing {}\n".format(name))
        if tactic not in output:
            output[tactic] = dict()
        mitigations = mitre_attack_data.get_mitigations_mitigating_technique(t_lookup[name].id)
        output[tactic][name] = [m["object"].name for m in mitigations]
        """
        import code
        code.interact(local=locals())
        """
        for m in mitigations:
            key = m["object"].name
            if key in merged_mits[tactic]:
                if name not in merged_mits[tactic][key]["techniques"]:
                    merged_mits[tactic][key]["techniques"].append(name)
                    merged_mits[tactic][key]["count"] += 1
            else:
                merged_mits[tactic][key] = {"id": m["object"].external_references[0].external_id, "description": m["object"].description, "techniques": [name], "count": 1}


def get_techniques(toExcel, layerInit, merged_techs, filename, filepath="layer.xlsx", source="local", resource="collections/enterprise.json"):
    if not isinstance(layerInit, Layer):
        raise TypeError

    layer = deepcopy(layerInit)
    filename = os.path.basename(filename)

    if toExcel.domain not in layer.layer.domain:
        raise ValueError(f"layer domain ({layer.layer.domain}) does not match exporter domain ({toExcel.domain})")

    included_subs = []
    if layer.layer.techniques:
        for entry in layer.layer.techniques:
            if entry.showSubtechniques:
                if entry.tactic:
                    included_subs.append((entry.techniqueID, entry.tactic))
                else:
                    included_subs.append((entry.techniqueID, False))

    excluded = []
    if layer.layer.hideDisabled:
        for entry in layer.layer.techniques:
            if entry.enabled is False:
                if entry.tactic:
                    excluded.append((entry.techniqueID, entry.tactic))
                else:
                    excluded.append((entry.techniqueID, False))
    
    codex = toExcel.raw_handle.h.get_matrix()
    techs = [t for (t, _) in included_subs ]
    if source == "local":
        mitre_attack_data = MitreAttackData(resource)
    else:
        mitre_attack_data = MitreAttackData("attack-stix-data/enterprise-attack/enterprise-attack.json")

    t_lookup = mitre_attack_data.get_techniques(remove_revoked_deprecated=True)
    t_lookup = dict([(t["name"],t) for t in t_lookup]) # eventually want to update with external id, ala t.get("external_references")
    output = dict()
    for tech in techs:
        (tactic, name) = get_name(codex, tech)
        if name not in t_lookup.keys():
            raise Exception("Missing {}\n".format(name))
        if tactic not in output:
            output[tactic] = dict()
        if tactic not in merged_techs:
            merged_techs[tactic] = dict()
        mitigations = mitre_attack_data.get_mitigations_mitigating_technique(t_lookup[name].id)
        output[tactic][name] = [m["object"].name for m in mitigations]
        if name in merged_techs[tactic]:
            if filename not in merged_techs[tactic][name]["sources"]:
                merged_techs[tactic][name]["sources"].append(filename)
                merged_techs[tactic][name]["count"] += 1
        else:
            merged_techs[tactic][name] = {"id": tech, "sources": [filename], "count": 1}


def main(argv=None):
    """Entrypoint for layerExporter_cli."""
    parser = argparse.ArgumentParser(description="Aggregate ATT&CK Navigator layers into JSON format")
    
    parser.add_argument("input", nargs="+", help="Path(s) to the file to export")
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
    parser.add_argument("-o", "--output", nargs="+", help="Path(s) to the aggregated json file", required=True)

    args = parser.parse_args(args=argv)

    merged_techs = OrderedDict()
    merged_mits = OrderedDict()
    tactics = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation", 
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", 
    "Command and Control", "Exfiltration", "Impact"]
    for t in tactics:
        merged_techs[t] = dict()
        merged_mits[t] = dict()
    for i in range(0, len(args.input)):
        entry = args.input[i]
        print(f"{i + 1}/{len(args.input)} - Beginning processing {entry}")
        lay = Layer()
        try:
            lay.from_file(entry)
        except Exception as e:
            print(f"Unable to load {entry} due to exception: {e}. Skipping...")
            continue

        tempF = tempfile.NamedTemporaryFile(suffix=".xlsx")
        exy = ToExcel(domain=lay.layer.domain, source=args.source, resource=args.resource)
        exy.to_xlsx(lay, filepath=tempF)
        json_fp= "tmp.json"
        get_techniques(exy, lay, merged_techs, entry, source=args.source, resource=args.resource, filepath=json_fp)
        get_mitigations(exy, lay, merged_mits, entry, source=args.source, resource=args.resource, filepath=json_fp)

        print(f"{i + 1}/{len(args.input)} - Finished exporting {entry}")

    for tactic in merged_techs:
        # data = dict([k, {"count": v["count"]}] for (k, v) in merged_techs[tactic].items())
        data = dict([k, v] for (k, v) in merged_techs[tactic].items())
        sortd = OrderedDict(sorted(data.items(), key=lambda item: item[1]['count'], reverse=True))
        merged_techs[tactic] = sortd

    for tactic in merged_mits:
        # data = dict([k, {"count": v["count"]}] for (k, v) in merged_mits[tactic].items())
        data = dict([k, v] for (k, v) in merged_mits[tactic].items())
        sortd = OrderedDict(sorted(data.items(), key=lambda item: item[1]['count'], reverse=True))
        merged_mits[tactic] = sortd

    tech_counts = {}
    for tactic in merged_techs:
        for tech in merged_techs[tactic]:
            if tech not in tech_counts:
                tech_counts[tech] = {"count": 0, "id": merged_techs[tactic][tech]["id"]}
            val = merged_techs[tactic][tech]
            tech_counts[tech][tactic] = val["count"]
            tech_counts[tech]["count"] += val["count"]

    sortd = OrderedDict(sorted(tech_counts.items(), key=lambda item: item[1]['count'], reverse=True))
    tech_counts = sortd

    mit_counts = {}
    for tactic in merged_mits:
        for mit in merged_mits[tactic]:
            if mit not in mit_counts:
                mit_counts[mit] = {"count": 0, "tactics": [tactic], "id": merged_mits[tactic][mit]["id"]}
                val = merged_mits[tactic][mit]
                for tech in val["techniques"]:
                    mit_counts[mit][tech] = tech_counts[tech]["count"]
                    mit_counts[mit]["count"] += tech_counts[tech]["count"]
            else:
                mit_counts[mit]["tactics"].append(tactic)

    sortd = OrderedDict(sorted(mit_counts.items(), key=lambda item: item[1]['count'], reverse=True))
    mit_counts = sortd

    # truncate
    sortd = OrderedDict(sorted(tech_counts.items(), key=lambda item: item[1]['count'], reverse=True))
    tech_counts = sortd

    out_file = os.path.basename(args.output[0])
    with open(out_file, "w") as fp:
        data = {"Techniques": tech_counts, "Mitigations": mit_counts}
        json.dump(data, fp, indent=4)

if __name__ == "__main__":
    main()

"""
example run:
python aggregateLayers.py -s local --resource collections/enterprise.json layer1.json layer2.json -o aggregate.json
"""