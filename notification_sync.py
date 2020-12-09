# Copyright © 2020 ThreatConnect, Inc. All rights reserved.
# Contributor: Cezanne Vahid
# Software License
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
# Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
# Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
# Neither the name of ThreatConnect, Inc. nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""ThreatConnect VT alert notifications app"""
#Cezanne Vahid
#cvahid@threatconnect.com

import requests
import json

from tc_dm import map_and_create
from job_app import JobApp

DATASTORE_HOME = 'virustotal'
DATASTORE_MAPPINGS = 'notification_mappings'
DATASTORE_LAST_ID = 'last_id'
DATASTORE_ID_LOOKUP_TABLE = 'id_lookup_table'

VT_NOTIFICATIONS_URL = 'https://www.virustotal.com/api/v3/intelligence/hunting_notification_files'


def get_notifications(vt_api_key, limit=None, cursor=None, vt_filter=None):
    params = {}
    if limit:
        params['limit'] = limit
    if vt_filter:
        params['filter'] = vt_filter
    if cursor:
        params['cursor'] = cursor
    response = requests.get(
        VT_NOTIFICATIONS_URL,
        headers={'x-apikey': vt_api_key},
        params=params
    ).json()
    new_cursor = response.get('meta', {'cursor': None}).get('cursor')
    yield response['data']
    if new_cursor:
        yield from get_notifications(vt_api_key, limit, new_cursor, vt_filter)
    else:
        yield None


class App(JobApp):
    """Job App"""
    
    def run(self):
        self.tcex.log.info('Notification Sync Starting.')
        ds = self.tcex.datastore('organization', DATASTORE_HOME)
        last_id = {}
        try:
            last_id = ds.get(rid=DATASTORE_LAST_ID)['_source']
        except RuntimeError as e:
            ds.add(rid=DATASTORE_LAST_ID, data=last_id)
        last_id = last_id.get('id')
        try:
            ilt = ds.get(rid=DATASTORE_ID_LOOKUP_TABLE)['_source']
        except RuntimeError as e:
            self.tcex.exit(1, 'Error fetching ID Lookup: {} Did you forget to run the rule sync?'.format(e.args[1]))
        try:
            mappings = ds.get(rid=DATASTORE_MAPPINGS)['_source']
            if isinstance(mappings, str):
                mappings = json.loads(mappings)
            if 'data' in mappings:
                mappings = mappings['data'] if isinstance(mappings['data'], dict) else json.loads(mappings['data'])  # probably not necessary but just to be safe
        except RuntimeError as e:
            self.tcex.exit(1, 'Problem fetching mapping: {}'.format(e.args[1]))  # tcex log
        count = 0
        last_found = False
        notifications = get_notifications(self.args.vt_api_key, limit=40)
        data = next(notifications)
        first_id = data[0]['context_attributes']['notification_id']
        while data:
            print('processing batch {}'.format(count))
            if last_id:
                ids = [i['context_attributes']['notification_id'] for i in data]
                try:
                    ind = ids.index(last_id)
                except ValueError:
                    pass
                else:
                    last_found = True
                    data = data[:ind]
            map_and_create(mappings, data, self.tcex, self.args.owner, count)
            for d in data:
                a = d['attributes']
                c = d['context_attributes']
                r_set = c['ruleset_name']
                r_name = c['rule_name']
                sig_id = ilt[r_set][r_name]['latest']
                sig_groups = ilt[r_set][r_name]['groups']

                file_ti = self.tcex.ti.indicator(indicator_type='File', owner=self.args.owner, unique_id=a['sha256'])
                sig_ti = self.tcex.ti.group(group_type='Signature', owner=self.args.owner, unique_id=sig_id)
                sig_ti.add_association(target=file_ti)
                for i in filter(lambda x: x['type'] == 'Incident', file_ti.group_associations()):
                    inc_ti = self.tcex.ti.group(group_type='Incident', owner=self.args.owner, unique_id=i['id'])
                    inc_ti.add_association(target=sig_ti)
                for sg in sig_groups:
                    group_ti = self.tcex.ti.group(group_type=sg['type'], owner=self.args.owner, unique_id=sg['id'])
                    group_ti.add_association(target=file_ti)
            if last_found:
                break
            count += len(data)
            data = next(notifications)
        ds.add(rid=DATASTORE_LAST_ID, data={"id": first_id})
        self.tcex.log.info('Notification Sync Complete.')
