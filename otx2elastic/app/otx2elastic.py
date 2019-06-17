#!/usr/bin/env python
#
# Wex Lambert, wlambertts@gmail.com
#
# A large portion of this code was originally written by Stephen Hosom with regard to pulling OTX
# pulses to use with Bro (https://github.com/hosom/bro-otx/).  
# The original script 'bro-otx.py' has been modified to be used with memcached to enrich Elasticseardh documents 

import requests
import sys
import os
from config import parser
from pymemcache.client.base import Client
from datetime import datetime, timedelta
import time

# The URL is hard coded. I'm comfortable doing this since it's unlikely that
# the URL will change without resulting in an API change that will require
# changes to this script.
_URL = 'http://otx.alienvault.com/api/v1/pulses/subscribed'

# Mapping of OTXv2 Indicator types to memcached key prefixes
_MAP = {
    "IPv4": "ip",
    "IPv6": "ip",
    "domain": "domain",
    "hostname": "domain",
    "email": "email",
    "URL": "domain",
    "URI": "domain",
    "FileHash-MD5": "md5",
    "FileHash-SHA1": "sha1",
    "FileHash-SHA256": "sha256",
}

def _get(key, mtime, limit=20, next_request=''):
    '''
    Retrieves a result set from the OTXv2 API using the restrictions of
    mtime as a date restriction.
    '''

    headers = {'X-OTX-API-KEY': key}
    params = {'limit': limit, 'modified_since': mtime}
    if next_request == '':
        r = requests.get(_URL, headers=headers, params=params)
    else:
        r = requests.get(next_request, headers=headers)

    # Depending on the response code, return the valid response.
    if r.status_code == 200:
        return r.json()
    if r.status_code == 403:
        print("An invalid API key was specified.")
        sys.exit(1)
    if r.status_code == 400:
        print("An invalid request was made.")
        sys.exit(1)

def iter_pulses(key, mtime, limit=20):
    '''
    Creates an iterator that steps through Pulses since mtime using key.
    '''

    # Populate an initial result set, after this the API will generate the next
    # request in the loop for every iteration.
    initial_results = _get(key, mtime, limit)
    for result in initial_results['results']:
        yield result

    next_request = initial_results['next']
    while next_request:
        json_data = _get(key, mtime, next_request=next_request)
        for result in json_data['results']:
            yield result
        next_request = json_data['next']

def map_indicator_type(indicator_type):
    '''
    Maps an OTXv2 indicator type to a memcached prefix that will be used during the lookup in the Logstash pipeline.
    '''

    return _MAP.get(indicator_type)

def runOTX():
    '''Retrieve intel from OTXv2 API.'''

    days = int(parser.get('otx', 'days_of_history'))
    key = parser.get('otx', 'api_key')
    mem_host = parser.get('memcached', 'mem_host')
    mem_port = int(parser.get('memcached', 'mem_port'))
    memcached = Client((mem_host, mem_port))
    memcached_agetime = int(parser.get('memcached', 'agetime'))
    memcached_sleeptime = int(parser.get('memcached', 'sleeptime'))
    mtime = (datetime.now() - timedelta(days=days)).isoformat()

    for pulse in iter_pulses(key, mtime):
            pulse_name = pulse['name']
            pulse_id = pulse['id']
            for indicator in pulse[u'indicators']:
                ioc = indicator['indicator']
                ioc_type = map_indicator_type(indicator[u'type'])
                tag = pulse_name + '-' + pulse_id
                if ioc_type is None:
                    continue
                try:
                    url = pulse[u'references'][0]
                except IndexError:
                    url = 'https://otx.alienvault.com'
                memcached_key = ioc_type +  '-' + ioc
                try:
                  memcached.set(memcached_key.encode('utf-8'), tag.encode('utf-8') , memcached_agetime)
                except:
                    pass
    time.sleep(memcached_sleeptime)
while True:
    runOTX()
