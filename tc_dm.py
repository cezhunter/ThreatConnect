# Copyright © 2020 ThreatConnect, Inc. All rights reserved.
# Contributor: Cezanne Vahid
# Software License
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
# Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
# Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
# Neither the name of ThreatConnect, Inc. nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


# ThreatConnect
# Cezanne Vahid
# cvahid@threatconnect.com
# ThreatConnect Data Mapper

import jmespath
import json

# TODO:
#
# Test on python3.8
# add logging that will attach to tcex app if not running standalone
# Add ability to add literals (raw strings and numbers)
# Potentially Add MultiProcessing
# Duplicate Indicators in Batch File will not be have associations with groups registered
# Take batch write type as arg (append or replace)

NON_ATTRIBUTES = ['fileOccurrence', 'size', 'tag', 'rating', 'confidence']
SINGLE_VALUED_FIELDS = ['size', 'rating', 'confidence']

class Funcs:

    def fileOccurrence(attr_type, vals, source):
        return [{'fileName': t} for t in vals]

    def tag(attr_type, vals, source):
        return [{'name': t} for t in vals]

    def attribute(attr_type, vals, source):
        r = [{'type': attr_type, 'value': v} for v in vals]
        if source:
            list(map(lambda x: x.update({'source': source}), r))
        return r

def add_data(objs, attr_type, attr_value, attr_source, one_to_one=False):  # add tag/attribute data to tc jsons, function can be cleaner
    """Adds new data to dictionaries for batch consumption."""
    field_name = attr_type
    if not isinstance(attr_value, list):
        attr_value = [attr_value]
    if attr_type not in NON_ATTRIBUTES:
        field_name = 'attribute'
    if one_to_one:
        if len(objs) != len(attr_value):
            return
        for obj, value in zip(objs, attr_value):
            if attr_type in SINGLE_VALUED_FIELDS:
                obj[attr_type] = value
            elif not isinstance(value, list):
                value = [value]
                obj.setdefault(field_name, list()).extend(
                    getattr(Funcs, field_name)(attr_type, value, attr_source))
    else:
        for obj in objs:
            if attr_type in SINGLE_VALUED_FIELDS:
                obj[attr_type] = attr_value[0]
            else:
                obj.setdefault(field_name, list()).extend(
                    getattr(Funcs, field_name)(attr_type, attr_value, attr_source))

def gen_tc_objects(group_types, batch, tc_type, items, gen):
    """Builds new dictionary for groups and indicators to be added to batch."""
    if not isinstance(items, list):
        items = [items]
    tc_type = tc_type.title()
    tc_objects = list()
    nf = 'summary'
    obj_type = 'indicator'
    if tc_type in group_types:
        obj_type = 'group'
        nf = 'name'
    for item in items:
        xid = batch.generate_xid(['dev', item, next(gen)])  # This may cause issues later
        tc_objects.append({
            nf: item,
            "xid": xid,
            "type": tc_type
        })
    return tc_objects, obj_type

def create_file_action(tcex, owner, source_object, target_object, relationship):  # batch does not accept file actions currently
    """Creates File Action associations in TC (Not supported in batch)."""
    object_resource1 = tcex.resource(source_object['type'].title())
    object_resource1.owner = owner
    object_resource1.resource_id(source_object['summary'].strip())
    object_resource2 = tcex.resource(target_object['type'].title())
    object_resource2.resource_id(target_object['summary'].strip())
    associations_resource = object_resource1.association_custom(relationship, object_resource2)
    associations_resource.http_method = 'POST'
    return associations_resource.request()

def gen_id(s):
    """Simple generator for creating xids"""
    while True:
        yield s
        s += 1

def map_and_create(mappings, data, tcex, owner, seed=0):
    """
        Takes a mappings JSON, a data JSON, an initialized TCEX instance, and an owner.
        Creates Data in ThreatConnect based on given mappings
    """
    global modules
    class modules:
        pass
    list(map(lambda mod: setattr(modules, mod, __import__(mod)), mappings.get('imports', [])))
    gen = gen_id(int(seed))
    batch = tcex.batch(owner, attribute_write_type='Replace')
    if mappings.get('iterative_path'):
        data = jmespath.search(mappings.get('iterative_path'), data)
    default_attribute_source = mappings.get('default_attribute_source')
    ns_list = list()
    for item in data:
        ns = dict()  # use namedtuples instead...
        for mapping in mappings['data_mappings']:
            obj_id = mapping.get('id')
            data_args = [jmespath.search(path, item) for path in mapping['sources']]
            if data_args == [None]:
                continue
            if mapping.get('function'):
                f = eval(mapping.get('function'))
                if mapping.get('one-to-one'):
                    target_data = list(map(f, data_args[0]))
                else:
                    target_data = f(*data_args)
            else:
                target_data = data_args[0]
            if obj_id:
                objs, obj_type = gen_tc_objects(
                    list(tcex.group_types_data.keys()),
                    batch,
                    mapping.get('target'),
                    target_data,
                    gen
                )
                ns.setdefault(obj_id, {'type': obj_type, 'objs': []})['objs'] += objs
            else:
                object_id, object_field = mapping.get('target').split(':')
                add_data(
                    ns[object_id]['objs'],
                    object_field,
                    target_data,
                    default_attribute_source or mapping.get('attribute_source'),
                    mapping.get('one-to-one')
                )
        ns_list.append(ns)
        for assoc in mappings['associations']:
            try:
                source_items = ns[assoc['source']]['objs']
                target_items = ns[assoc['target']]['objs']
            except KeyError:
                continue
            target_type = ns[assoc['target']]['type']
            for item in target_items:
                assocs_name = 'associatedGroups'
                assocs = [{'groupXid': g['xid']} for g in source_items]
                if target_type == 'group':
                    assocs_name = 'associatedGroupXid'
                    assocs = [g['xid'] for g in source_items]
                item.setdefault(assocs_name, []).extend(assocs)
        deduplicated_indicators = dict()
        for item in ns.values():
            objs = item['objs']
            obj_type = item['type']
            if obj_type == 'group':
                for g in objs:
                    batch.add_group(g)
            elif obj_type == 'indicator':
                for i in objs:
                    if i['summary'] not in deduplicated_indicators:
                        deduplicated_indicators[i['summary']] = i
                    else:
                        deduplicated_indicators[i['summary']].setdefault(
                            'associatedGroups', []
                        ).extend(i.get('associatedGroups', []))
        list(map(batch.add_indicator, deduplicated_indicators.values()))
    # with open('batch_{}.json'.format(seed), 'w') as file:
    #     file.write(str(batch))
    batch_data = batch.submit_all()
    file_action_results = list()
    for ns in ns_list:
        for assoc in list(filter(lambda x: x.get('type'), mappings['associations'])):
            try:
                source_items = ns[assoc['source']]['objs']
                target_items = ns[assoc['target']]['objs']
            except KeyError:  # id never created
                continue
            association_type = assoc['type']
            for source_item in source_items:
                for target_item in target_items:
                    r = create_file_action(tcex, owner, source_item, target_item, association_type)
                    log_dict = {
                        'source_file': source_item['summary'],
                        'target_file': target_item['summary'],
                        'type': association_type,
                        'status': r['status']
                    }
                    file_action_results.append(log_dict)
    # with open('batch_results.json', 'w') as file:  # add to batch logs dir
    #     file.write(json.dumps(batch_data, indent=4))
    # with open('file_action_results.json', 'w') as file:
    #     file.write(json.dumps(file_action_results, indent=4))
    # print('Wrote batch and file action responses to files.')