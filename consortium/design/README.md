0. install dependencies

`pip install mitreattack-python`

1. Combine navigation layers for money movement threat actors to get a combined list of relevant MITRE ATT&CK techniques & mitigations

`python aggregateLayers.py -s local --resource collections/enterprise.json money_movement/apt38_\(g0082\).json money_movement/cobalt_group_\(g0080\).json money_movement/G0008-enterprise-layer.json money_movement/G0032-enterprise-layer.json money_movement/G0138-enterprise-layer.json  -o aggregate.json`

2. Go to `mappings` dir to find scripts that translate from MITRE ATT&CK to control frameworks
