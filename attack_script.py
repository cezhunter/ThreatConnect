# Copyright © 2020 ThreatConnect, Inc. All rights reserved.
# Contributor: Cezanne Vahid
# Software License
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
# Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
# Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
# Neither the name of ThreatConnect, Inc. nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Cezanne Vahid
# cvahid@threatconnect.com
#
# ATT&CK STIX JSON --> TC via Batch
# Requires:
#   - TC Config File
#   - Target Source
#   - Up-to-date MITRE links

import argparse
import jmespath
import json
import requests

from tcex import TcEx

# MITRE
ENT_ATTACK_URL = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
PRE_ATTACK_URL = 'https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json'

# JMES PATHs
JMES_PATH_TECHNIQUES = 'objects[?type == `attack-pattern`]'
JMES_PATH_RELATIONSHIPS = 'objects[?type == `relationship`]'
JMES_PATH_MITIGATION = 'objects[?type == `course-of-action`]'
JMES_PATH_MITIGATION_FORMAT_1 = '[?target_ref == `{}`] | [?contains(source_ref, `course-of-action`) ].source_ref'
JMES_PATH_MITIGATION_FORMAT_2 = 'to_array([?id == `{}`])[0]'

# Mappings and Formating
TAG_FORMAT = '{id} - {name} - {phase} - {model} - ATT&CK'

TACTIC_ACRO_MAPPING = {
    'collection': 'COL',
    'persistence': 'PER',
    'execution': 'EXE',
    'credential-access': 'CRA',
    'lateral-movement': 'LAT',
    'initial-access': 'INI',
    'defense-evasion': 'DEF',
    'command-and-control': 'C&C',
    'discovery': 'DIS',
    'exfiltration': 'EXF',
    'privilege-escalation': 'PRI',
    'impact': 'IMP',
    'priority-definition-planning': 'PDP',
    'priority-definition-direction': 'PDD',
    'target-selection': 'TAR',
    'technical-information-gathering': 'TIG',
    'people-information-gathering': 'PIG',
    'organizational-information-gathering': 'OIG',
    'technical-weakness-identification': 'TWI',
    'people-weakness-identification': 'PWI',
    'organizational-weakness-identification': 'OWI',
    'adversary-opsec': 'AOP',
    'establish-&-maintain-infrastructure': 'EMI',
    'persona-development': 'PDV',
    'build-capabilities': 'BDC',
    'test-capabilities': 'TST',
    'stage-capabilities': 'STG',
    'launch': 'LNC',
    'compromise': 'COM'
}

HEADER_URL = '####Entry URL\n'
HEADER_CITATION = '####Citation\n'
HEADER_CONTRIBUTORS = '####Contributors\n'
HEADER_DETECTION = '####Detection\n'
HEADER_DATA_SOURCES = '####Data Sources\n'
HEADER_PLATFORMS = '####Platforms\n'
HEADER_PERMISSIONS = '####Effective Permissions\n'
HEADER_NETWORK_REQUIREMENTS = '####Network Requirements\n'
HEADER_PERMISSION_REQUIRED = '####Permissions Required\n'
HEADER_REMOTE_SUPPORT = '####Remote Support\n'
HEADER_SYSTEM_REQUIREMENTS = '####System Requirements\n'
HEADER_DEFENSE_BYPASSED = '####Defense Bypassed\n'
HEADER_MITIGATIONS = '####Mitigations\n'
HEADER_DIFFICULTY_ADVERSARY = '####Difficulty for Adversary\n'
HEADER_EXPLANATION_ADVERSARY = '####Difficulty for Adversary Explanation\n'
HEADER_EXPLANATION_DEFENSE = '####Detectable by Common Defenses Explanation\n'
HEADER_DETECTABLE = '####Detectable by Common Defenses\n'


def main():
    parser = argparse.ArgumentParser(
        description='Take a tc config path and a target \
        source and then populate with ATT&CK data.'
    )
    parser.add_argument(
        'config_path',
        metavar='config_path',
        type=str,
        help='ThreatConnect config JSON path.'
    )
    parser.add_argument(
        '--target',
        dest='target_source',
        metavar='target_source',
        type=str,
        help='ThreatConnect target source to populate \
        with ATT&CK data. Default is MITRE ATT&CK.',
        default='MITRE ATT&CK'
    )
    parser.add_argument(
        '--v',
        action='store_true',
        help='Verbose mode, print entire batch response.',
        default=False
    )
    args = parser.parse_args()
    tcex = TcEx(config_file=args.config_path)  # command args probably
    try:
        batch = tcex.batch(args.target_source)
    except AttributeError:
        print('Please check your tc config file path.')

    response = requests.get(ENT_ATTACK_URL)
    if response.status_code not in [200, 201]:
        print('Error encountered while attemtping \
            to download MITRE ATT&CK Enterprise JSON: {}'.format(response.text))
        return
    ent_data = response.json()

    response = requests.get(PRE_ATTACK_URL)
    if response.status_code not in [200, 201]:
        print('Error encountered while attemtping \
            to download MITRE ATT&CK Pre-Att&ck JSON: {}'.format(response.text))
        return
    pre_data = response.json()

    combined = {'objects': pre_data['objects'] + ent_data['objects']}

    # new_string = response.text.replace('<code>', '').replace('</code>', '')
    technique_objects = jmespath.search(JMES_PATH_TECHNIQUES, combined)
    relationship_objects = jmespath.search(JMES_PATH_RELATIONSHIPS, combined)
    mitigation_objects = jmespath.search(JMES_PATH_MITIGATION, combined)

    c = 0
    for obj in technique_objects:
        stix_id = obj['id']
        mitre_url = obj['external_references'][0]['url']
        mitre_id = obj['external_references'][0]['external_id']
        mitre_source = obj['external_references'][0]['source_name']
        mitre_name = obj['name']
        # trunc_name = obj['name'][:96]+'...' if len(mitre_name) >= 99 else mitre_name
        tc_source = ''
        tc_aac = ''
        tc_capabilities = ''
        tc_coar = ''
        tc_desc = ''

        xid = batch.generate_xid(['att&ck', 'threat', c])
        tc_group_obj = {
            'type': 'Threat',
            'xid': xid,
            'name': '{} {}'.format(mitre_id, mitre_name)
        }
        tc_attributes = list()
        if len(obj['external_references']) > 1:
            tc_source += HEADER_URL + mitre_url + '\n' + HEADER_CITATION
            for item in obj['external_references'][1:]:
                er_source_name = item.get('source_name')
                er_url = item.get('url')
                et_description = item.get('description')
                tc_source += '*{}*\n'.format(er_source_name) if er_source_name else ''
                tc_source += '*{}*\n'.format(er_url) if er_url else ''
                tc_source += '*{}*\n'.format(et_description) if et_description else ''
        if obj.get('x_mitre_contributors'):
            tc_source += '####Contributors\n'
            for cont in obj.get('x_mitre_contributors'):
                tc_source += '* {}\n'.format(cont.title())
        if obj.get('x_mitre_detection'):
            tc_aac += HEADER_DETECTION + obj.get('x_mitre_detection') + '\n\n'

        if obj.get('x_mitre_data_sources'):
            tc_aac += HEADER_DATA_SOURCES
            for src in obj.get('x_mitre_data_sources'):
                tc_aac += '* {}\n'.format(src)

        if obj.get('x_mitre_platforms'):
            tc_capabilities += HEADER_PLATFORMS
            for platform in obj.get('x_mitre_platforms'):
                tc_capabilities += '* {}\n'.format(platform.title())
            tc_capabilities += '\n'

        if obj.get('x_mitre_effective_permissions'):
            tc_capabilities += HEADER_PERMISSIONS
            for perm in obj.get('x_mitre_effective_permissions'):
                tc_capabilities += '* {}\n'.format(perm.title())
            tc_capabilities += '\n'

        if obj.get('x_mitre_permissions_required'):
            tc_capabilities += HEADER_PERMISSION_REQUIRED
            for perm in obj.get('x_mitre_permissions_required'):
                tc_capabilities += '* {}\n'.format(perm.title())
            tc_capabilities += '\n'

        if obj.get('x_mitre_system_requirements'):
            tc_capabilities += HEADER_SYSTEM_REQUIREMENTS
            for req in obj.get('x_mitre_system_requirements'):
                tc_capabilities += '* {}\n'.format(req)
            tc_capabilities += '\n'

        if obj.get('x_mitre_defense_bypassed'):
            tc_capabilities += HEADER_DEFENSE_BYPASSED
            for defense in obj.get('x_mitre_defense_bypassed'):
                tc_capabilities += '* {}\n'.format(defense)
            tc_capabilities += '\n'

        if obj.get('x_mitre_network_requirements'):
            tc_capabilities += HEADER_NETWORK_REQUIREMENTS
            tc_capabilities += '*{}*\n'.format(bool_to_yes_no(str(obj.get('x_mitre_network_requirements'))))

        if obj.get('x_mitre_remote_support'):
            tc_capabilities += HEADER_REMOTE_SUPPORT
            tc_capabilities += '*{}*\n'.format(bool_to_yes_no(str(obj.get('x_mitre_remote_support'))))

        if obj.get('description'):
            tc_desc = obj.get('description')

        if obj.get('x_mitre_difficulty_for_adversary'):
            tc_aac += HEADER_DIFFICULTY_ADVERSARY
            tc_aac += '*{}*\n\n'.format(bool_to_yes_no(str(obj.get('x_mitre_difficulty_for_adversary'))))
        if obj.get('x_mitre_difficulty_for_adversary_explanation'):
            tc_aac += HEADER_EXPLANATION_ADVERSARY
            tc_aac += obj.get('x_mitre_difficulty_for_adversary_explanation') + '\n\n'
        if obj.get('x_mitre_detectable_by_common_defenses'):
            tc_aac += HEADER_DETECTABLE
            tc_aac += '*{}*\n\n'.format(bool_to_yes_no(str(obj.get('x_mitre_detectable_by_common_defenses'))))
        if obj.get('x_mitre_detectable_by_common_defenses_explanation'):
            tc_aac += HEADER_EXPLANATION_DEFENSE
            tc_aac += obj.get('x_mitre_detectable_by_common_defenses_explanation') + '\n\n'

        # Fetch Mitigations
        mitigation_ids = jmespath.search(
            JMES_PATH_MITIGATION_FORMAT_1.format(stix_id),
            relationship_objects
        )
        if mitigation_ids:
            tc_coar += HEADER_MITIGATIONS
            for mitigation_id in mitigation_ids:
                mitigation_data = jmespath.search(
                    JMES_PATH_MITIGATION_FORMAT_2.format(mitigation_id),
                    mitigation_objects
                )
                if not mitigation_data.get('x_mitre_deprecated'):
                    tc_coar += '{} : {}\n\n'.format(
                        mitigation_data['name'],
                        mitigation_data['description']
                    )
        if tc_coar == HEADER_MITIGATIONS:
            tc_coar = ''
        # tc_capabilities = tc_capabilities if len(tc_capabilities) < 500 else '{}...'.format(tc_capabilities[:497])

        # Build Tags
        mitre_tactics = [item['phase_name'] for item in obj['kill_chain_phases']]
        tc_tags = [TAG_FORMAT.format(
            id=mitre_id,
            name=mitre_name,
            phase=TACTIC_ACRO_MAPPING[t],
            model='ENT'
            ) for t in mitre_tactics]
        if len(mitre_tactics) > 1:
            tc_tags.append(TAG_FORMAT.format(
                id=mitre_id,
                name=mitre_name,
                phase='NDT',
                model='ENT'))
        tc_tags += [i.title() for i in mitre_tactics]
        tc_tags += ['PRE-ATT&CK'] if mitre_source == 'mitre-pre-attack' else ['Enterprise ATT&CK']
        tc_tags = [{'name': t} for t in tc_tags]
        if tc_source:
            tc_attributes.append({
                'type': 'Source',
                'value': tc_source
            })
        if tc_aac:
            tc_attributes.append({
                'type': 'Additional Analysis and Context',
                'value': tc_aac
            })
        if tc_capabilities:
            tc_attributes.append({
                'type': 'Capabilities',
                'value': tc_capabilities
            })
        if tc_coar:
            tc_attributes.append({
                'type': 'Course of Action Recommendation',
                'value': tc_coar
            })
        if tc_desc:
            tc_attributes.append({
                'displayed': True,
                'type': 'Description',
                'value': tc_desc
            })

        tc_group_obj['attribute'] = tc_attributes
        tc_group_obj['tag'] = tc_tags
        batch.add_group(tc_group_obj)
        c += 1
    batch_data = batch.submit_all()
    if args.v:
        print(json.dumps(batch_data, indent=4))
    else:
        print(
            'Batch Response:\n\
            {0:<15} {4:>15}\n\
            {1:<15} {5:>15}\n\
            {2:<15} {6:>15}\n\
            {3:<15} {7:>15}\n'.format(
                'id',
                'status',
                'error count',
                'success count',
                str(batch_data[0].get('id')),
                batch_data[0].get('status'),
                str(batch_data[0].get('errorCount')),
                str(batch_data[0].get('successCount'))
            )
        )


def bool_to_yes_no(string):
    return string.replace('True', 'Yes').replace('False', 'No')


if __name__ == "__main__":
    main()
