# Copyright © 2020 ThreatConnect, Inc. All rights reserved.
# Contributor: Cezanne Vahid
# Software License
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
# Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
# Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
# Neither the name of ThreatConnect, Inc. nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


# ThreatConnect Yara Rule Sync
# Cezanne Vahid
# cvahid@threatconnect.com

import requests
from tcex import TcEx
from plyara import Plyara, utils
import json



"""Move below back to config file"""
VT_API_KEY = ""
RULESET_URL = "https://www.virustotal.com/api/v3/intelligence/hunting_rulesets"
TC_CONFIG = {
    "api_access_id": "",
    "api_default_org": "",
    "api_secret_key": "",
    "tc_api_path": "",
    "tc_log_level": "debug",
    "tc_log_path": "log",
    "tc_token": "",
    "tc_token_expires": 0
}

DATASTORE_HOME = 'virustotal'
DATASTORE_UPDATES_TABLE = 'last_update_table'
DATASTORE_MAPPINGS = 'rule_mappings'
DATASTORE_ID_LOOKUP_TABLE = 'id_lookup_table'
OWNER = 'Research Labs'

tcex = TcEx(config=TC_CONFIG)


def get_rulesets(limit=None, cursor=None, vt_filter=None):
    params = {}
    if limit:
        params['limit'] = limit
    if vt_filter:
        params['filter'] = vt_filter
    if cursor:
        params['cursor'] = cursor
    response = requests.get(
        RULESET_URL,
        headers={'x-apikey': VT_API_KEY},
        params=params
    ).json()
    new_cursor = response.get('meta', dict()).get('cursor')
    yield response['data']
    if new_cursor:
        yield from get_rulesets(limit, new_cursor, vt_filter)
    else:
        yield list()


def create_rules_in_tc(rules, raw_rules, ruleset_name, id_lookup_table, mappings):
    # TODO: Add meta fields as tags (Sandbox Restricted)
    groups = tcex.ti.group(owner=OWNER)  # Owner might need to be brought up as an arg
    parameters = {'includes': ['additional', 'attributes', 'labels', 'tags']}
    for rule in rules:
        rule_name = rule['rule_name']
        rule_content = utils.rebuild_yara_rule(rule)
        lookup_context = id_lookup_table.setdefault(
            ruleset_name, dict()).setdefault(
                rule_name, dict())
        versions = lookup_context.setdefault(
            'versions', dict())
        groups = lookup_context.setdefault(
            'groups', list())
        group_created = False
        lookup_context['priority'] = next(filter(lambda x: 'priority' in x, rule.get('metadata', [])), None)
        lookup_context['restricted'] = next(filter(lambda x: 'sandbox_restricted' in x, rule.get('metadata', [])), None)
        version = next(filter(lambda x: 'version' in x, rule.get('metadata', [])), None) or '1.0'
        signature_name = '{} : {} V{}'.format(ruleset_name, rule_name, version)
        kwargs = {
            'group_type': 'Signature',
            'name': signature_name,
            'file_name': '{}.yara'.format(rule_name),
            'file_type': 'YARA',
            'file_text': rule_content,
            'owner': OWNER
        }
        try:
            existing_id = lookup_context['versions'][version]
        except KeyError:
            existing_id = False
            signature_ti = tcex.ti.group(**kwargs)
            r = signature_ti.create()
            response_id = r.json()['data']['signature']['id']
            for v in versions:
                version_ti = tcex.ti.group(group_type='Signature', unique_id=versions[v], owner=OWNER)
                signature_ti.add_association(target=version_ti)
            versions[version] = response_id
            lookup_context['latest'] = response_id
        else:
            kwargs['unique_id'] = existing_id
            signature_ti = tcex.ti.group(**kwargs)
            list(
                map(signature_ti.delete_attribute,
                    [item['id'] for item in signature_ti.attributes()]))
            list(
                map(signature_ti.delete_tag,
                    [item['name'] for item in signature_ti.tags()]))
            signature_ti.update()

        for meta in rule.get('metadata', []):
            if not meta:
                continue
            attr_type, attr_value = meta.popitem()
            if attr_type in mappings.get('associations', dict()):
                group_type = mappings['associations'][attr_type]
                for group_name in attr_value.split(','):
                    filters = tcex.ti.filters()
                    filters.add_filter('name', '=', group_name)
                    a_groups = tcex.ti.group(group_type=group_type, owner=OWNER)
                    returned_groups = list(a_groups.many(filters=filters, params=parameters))
                    if not returned_groups:
                        group_ti = tcex.ti.group(group_type=group_type, name=group_name, owner=OWNER)
                        r = group_ti.create()
                        groups.append({
                            'name': group_name,
                            'id': r.json()['data'][group_type.lower()]['id'],
                            'type': group_type
                        })
                        signature_ti.add_association(target=group_ti)
                        continue
                    for g in returned_groups:
                        group_ti = tcex.ti.group(group_type=group_type, unique_id=g['id'], owner=OWNER)
                        groups.append({
                            'name': group_name,
                            'id': g['id'],
                            'type': group_type
                        })
                        signature_ti.add_association(target=group_ti)
                group_created = True
            elif attr_type == 'tags' and mappings.get('tags'):
                list(map(
                    lambda tag: signature_ti.add_tag(name='τ {}'.format(tag)),
                    attr_value.split(',')))
            elif attr_type in mappings.get('boolean_tags', []) and attr_value:
                signature_ti.add_tag(name='ζ {}'.format(attr_type.replace('_', ' ').title()))
            elif mappings.get('attributes', dict()).get(attr_type):
                signature_ti.add_attribute(
                    attribute_type=mappings['attributes'].get(attr_type),
                    attribute_value=attr_value
                )
        if not group_created and mappings.get('default_association'):
            group_ti = tcex.ti.group(
                group_type=mappings['default_association'],
                name=rule_name,
                owner=OWNER)
            r = group_ti.create()
            groups.append({
                'name': rule_name,
                'id': r.json()['data'][mappings['default_association'].lower()]['id'],
                'type': mappings['default_association']
            })
            signature_ti.add_association(target=group_ti)
        signature_ti.add_tag(name='α {}'.format(ruleset_name))
        signature_ti.add_tag(name='β {}'.format(rule_name))

def main():
    parser = Plyara()
    ds = tcex.datastore('organization', DATASTORE_HOME)
    updates_table = id_lookup_table = {}
    # ds.add(rid=DATASTORE_UPDATES_TABLE, data=updates_table)  # uncomment to wipe ds
    # ds.add(rid=DATASTORE_ID_LOOKUP_TABLE, data=id_lookup_table)
    # return
    try:
        updates_table = ds.get(rid=DATASTORE_UPDATES_TABLE)['_source']
    except RuntimeError:
        ds.add(rid=DATASTORE_UPDATES_TABLE, data=updates_table)
    try:
        id_lookup_table = ds.get(rid=DATASTORE_ID_LOOKUP_TABLE)['_source']
    except RuntimeError:
        ds.add(rid=DATASTORE_ID_LOOKUP_TABLE, data=id_lookup_table)
    try:
        mappings = ds.get(rid=DATASTORE_MAPPINGS)['_source']
        if isinstance(mappings, str):
            mappings = json.loads(mappings)
        if 'data' in mappings:
            mappings = mappings['data'] if isinstance(mappings['data'], dict) else json.loads(mappings['data'])  # probably not necessary but just to be safe
    except RuntimeError as e:
        print(e.args[1])  # tcex log
        return
    r = get_rulesets(limit=40)
    data = next(r)
    while data:
        for ruleset in data:
            modification_date = ruleset['attributes']['modification_date']
            ruleset_name = ruleset['attributes']['name']
            ruleset_id = ruleset['id']
            last_update = updates_table.get(ruleset_id)
            # last_update = False  # uncomment when testing
            if not last_update or modification_date > last_update:
                raw_rules = ruleset['attributes']['rules']
                rules = parser.parse_string(raw_rules)
                create_rules_in_tc(rules, raw_rules.split('\n'), ruleset_name, id_lookup_table, mappings)
                print('{} Ruleset Processed'.format(ruleset_name))
            updates_table[str(ruleset_id)] = modification_date
            parser.clear()
        data = next(r)
    ds.add(rid=DATASTORE_UPDATES_TABLE, data=updates_table)
    ds.add(rid=DATASTORE_ID_LOOKUP_TABLE, data=id_lookup_table)

main()