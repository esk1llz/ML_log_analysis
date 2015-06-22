#!/usr/bin/env python3

#
# esindex.py - communicates with elasticsearch to index outlier results
#
# File 5/6 - 'esindex.py'
# See also 'escontrol.py'
# See also 'esquery.py'
# See also 'esvectorize.py'
# See also 'esanalyze.py'
# See also 'esconstants.py'
#

# Version:    1.0
# Created:    2015-04-01
# Revision:   yyyy-mm-dd
# Revised by: First Last

import traceback
import sys
import json
from datetime import *
import dateutil.parser
import pytz
from pytz import timezone

import requests
from socket import error as SocketError
from urllib3.exceptions import ProtocolError
from requests.exceptions import ConnectionError

import esconstants


class ESIndex(object):
    '''
    An Elasticsearch reindex and update task, contains associated responses
    and records as returned from the Elasticsearch key-value datastore.

    Attributes:
        self.test_date: Date of the dataset under test
        self.outliers: A series of alert times by type and subtype
        self.response: Server responses to POSTed queries
        self.records: Server responses to POSTed entry updates
        self._json_data: Temporary generated POST data for indexing
        self._SUBTYPE_KEY: An elasticsearch key lookup table by log type
        self._SUBTYPE_TAG: A tagging lookup table by log type
    '''
    def __init__(self, test_date, outliers):
        self.test_date = test_date
        self.outliers = outliers
        self.response = {}
        self.records = {}
        self._json_data = ''
        self._SUBTYPE_KEY = {'ossec': esconstants.KEY_OSSEC_RULE,
                             'syslog': esconstants.KEY_SYSLOG_SEV,
                             'suricata': esconstants.KEY_SURICATA_SIG}
        self._SUBTYPE_TAG = {'ossec': esconstants.TAG_OSSEC,
                             'syslog': esconstants.TAG_SYSLOG,
                             'suricata': esconstants.TAG_SURICATA}

    def index(self):
        '''
        (self) -> None
        POSTs results to elasticsearch for indexing
        '''
        # index each outlier by type and subtype
        for type_key in self.outliers.keys():
            for subtype in self.outliers[type_key].keys():
                # keep a record of entries to alter
                if type_key not in self.response.keys():
                    self.response[type_key] = {}
                if subtype not in self.response[type_key].keys():
                    self.response[type_key][subtype] = []
                # keep a record of alteration outcomes
                if type_key not in self.records.keys():
                    self.records[type_key] = {}
                if subtype not in self.records[type_key].keys():
                    self.records[type_key][subtype] = []
                for outlier in self.outliers[type_key][subtype]:

                    # perform REST calls over network
                    try:
                        # ready DSL search query for outlying entries
                        url, json_data = self._build_query(type_key, subtype,
                                                outlier)
                        # execute query, convert to json from bytes
                        data = json.dumps(json_data)
                        results = requests.post(url, data).json()
                        self.response[type_key][subtype].append(results)

                        # perform elastic search indexing of results
                        for result in results[esconstants.KEY_ES_SEARCH][
                                 esconstants.KEY_ES_SEARCH]:
                            url, json_data = self._build_index(type_key,
                                   subtype, outlier, result)
                            # execute index, convert to json from bytes
                            data = json.dumps(json_data)
                            record = requests.post(url, data).json()
                            self.records[type_key][subtype].append(record)

                    except (SocketError, ProtocolError, ConnectionError):
                        print('Connection refused. (Check host IP)')
                        sys.exit(1)
                    except:
                        print('Error, quitting.')
                        traceback.print_exc()
                        sys.exit(1)

    def _build_query(self, type_key, subtype, outlier):
        '''
        (self, argparse.Namespace) -> None
        Build JSON POST data to retrieve outlying entry IDs
        '''
        # build body of elasticsearch index query
        query_final = {}
        timestamp = (datetime.now(pytz.timezone(esconstants.TIMEZONE)) -
                timedelta(days=(esconstants.TEST_DAY)))
        # hack the timestamps to match logstash generated representations
        timestamp1 = (timestamp.replace(hour=outlier, minute=0, second=0,
                microsecond=0))
        timestamp2 = (timestamp1.replace(minute=59, second=59,
                microsecond=999))
        # syslog is only log type that shifts for EST in kibana
        if type_key == esconstants.KEY_SYSLOG_TYPE:
            timestamp1 = str(timestamp1.isoformat()[:19] + '.000Z')
            timestamp2 = str(timestamp2.isoformat()[:19] + '.000Z')
        else:
            timestamp1 = timestamp1.isoformat()
            timestamp2 = timestamp2.isoformat()

        # retrieve all entries of the outlier type within time period
        index = esconstants.ES_INDEX_PREFIX + \
                self.test_date.isoformat()[:10].replace('-', '.')
        url = ('http://' + esconstants.ES_HOST + ':' +
                esconstants.ES_PORT + '/' + index + '/' +
                '_search')
        # make a boolean query for needed type and subtype
        dsl_query = {'query': {'bool': {'must': [
                {'term': {'type': type_key}},
                {'term': {self._SUBTYPE_KEY[type_key]: subtype}}]}}}
        # add time range filter
        dsl_temp = {}
        dsl_filter = {'filter': {'range': {'@timestamp': \
                        {'gte': timestamp1, 'lte': timestamp2}}}}
        dsl_query.update(dsl_filter)
        dsl_temp['filtered'] = dsl_query
        # wrap in one more query tag
        dsl_query = dsl_temp
        query_final['query'] = dsl_query
        # add field filter for entry id
        dsl_source = {'fields': '_id'}
        query_final.update(dsl_source)
        # add size field as arbitrarily large value
        dsl_size = {}
        dsl_size['size'] = esconstants.ES_QUERY_SIZE
        query_final.update(dsl_size)

        return url, query_final

    def _build_index(self, type_key, subtype, outlier, esentry):
        '''
        (self, argparse.Namespace) -> None
        Build JSON POST data to tag outlying entries as alerts
        *** Minor problem - when updating tags, overwrites existing
        *** tags - investigate why. This behaviour doesn't have a
        *** negative impact on this project.
        '''
        # build body of elasticsearch index query
        json_data = {}
        timestamp = (datetime.now(pytz.timezone(esconstants.TIMEZONE)) -
                timedelta(days=(esconstants.TEST_DAY)))
        # hack the timestamps to match logstash generated representations
        timestamp1 = (timestamp.replace(hour=outlier, minute=0, second=0,
                microsecond=0))
        timestamp2 = (timestamp1.replace(minute=59, second=59,
                microsecond=999))
        # syslog is only log type that shifts for EST in kibana
        if type_key == esconstants.KEY_SYSLOG_TYPE:
            timestamp1 = str(timestamp1.isoformat()[:19] + '.000Z')
            timestamp2 = str(timestamp2.isoformat()[:19] + '.000Z')
        else:
            timestamp1 = timestamp1.isoformat()
            timestamp2 = timestamp2.isoformat()

        # build URI and index data
        index = esconstants.ES_INDEX_PREFIX + \
                self.test_date.isoformat()[:10].replace('-', '.')
        esid = esentry[esconstants.KEY_ES_ID]
        url = ('http://' + esconstants.ES_HOST + ':' + esconstants.ES_PORT +
                '/' + index + '/' + type_key + '/' + esid + '/_update')
        json_data = {'doc': {'tags': [self._SUBTYPE_TAG[type_key]]}}
        return url, json_data
