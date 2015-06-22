#!/usr/bin/env python3

#
# esquery.py - communicates w elasticsearch & parses json
#
# File 2/6 - 'esquery.py'
# See also 'escontrol.py'
# See also 'esvectorize.py'
# See also 'esanalyze.py'
# See also 'esindex.py'
# See also 'esconstants.py'
#
# usage: esquery.py [-h] (-a [{stringquery,termquery,count}] | -q QUERY)
#                   (-l | -t TERMS) [-d [HOST]] [-i [INDEX]] [-s [SIZE]]
#                   [-r RANGE RANGE RANGE] [-f FIELDS [FIELDS ...]] [-c]
#
# esquery 0.1
#
# optional arguments:
#  -h, --help            show this help message and exit
#  -a [{stringquery,termquery,count}], --action [{stringquery,termquery,count}]
#                        actions wrap common query types (default:stringquery)
#                        - mutually exclusive of --query
#  -q QUERY, --query QUERY
#                        raw elasticsearch json query
#  -l, --list            display available indices - mutually exclusive of
#                        --terms
#  -t TERMS, --terms TERMS
#                        some text to query - format for stringquery is STRING,
#                        format for termquery is TERM:STRING
#  -d [HOST], --host [HOST]
#                        the elasticsearch host IP (default: localhost)
#  -i [INDEX], --index [INDEX]
#                        specifies a specific index to query (default:all)
#  -s [SIZE], --size [SIZE]
#                        number of hits to return (default: 10)
#  -r RANGE RANGE RANGE, --range RANGE RANGE RANGE
#                        range filter, specify field then beginning and end
#                        points as numeric arguments or in YYYY-MM-DD format
#                        for dates eg; --range severity 5 9 or -r timestamp
#                        2015-03-05 2015-03-11
#  -f FIELDS [FIELDS ...], --fields FIELDS [FIELDS ...]
#                        specify source fields to include in search
#                        (default:all fields)
#  -c, --count           return a count of hits only
#

# Version:    1.0
# Created:    2015-03-11
# Revision:   yyyy-mm-dd
# Revised by: First Last

import traceback
import sys
import argparse
import json
import requests
from socket import error as SocketError
from urllib3.exceptions import ProtocolError
from requests.exceptions import ConnectionError

import esconstants  # constants namespace

class ESQuery(object):
    '''
    An Elasticsearch query and associated response

    Attributes:
        response: JSON response returned by elasticsearch
        _query: The query string
        _json: Flag to determine if REST response should be printed as json
        _agg: A flag to enable support of elasticsearch aggregation
    '''

    def __init__(self):
        '''
        (self) -> ESQuery
        Initializes a new ESQuery object
        '''
        self.response = ''   # receive server response
        self._query = ''     # store the query
        self._json = True    # json flag for output
        self._agg = False    # print aggregation if true

    def post(self, args):
        '''
        (self, argparse.Namespace) -> None
        Make a query to elasticsearch
        '''
        list_flag = args.list
        host = args.host

        if args.terms != None:
            params = args.terms
        else:
            params = ''

        # perform REST calls over network
        try:
            # list elasticsearch indices
            if list_flag == True:
                call = '_cat/indices'
                params = '?v'
                self.response = requests.get('http://' + host + ':' +
                                             esconstants.ES_PORT +
                                             '/' + call + params)
                self._json = False
            # perform DSL search query
            else:
                url = self._build_query(args)
                data = json.dumps(self._query)
                self.response = requests.post(url, data)

            # if the query was an index query, print result to console
            if not self._json:
                self._print_indices(self.response)

        except (SocketError, ProtocolError, ConnectionError):
            print('Connection refused. (Check --host IP)', file=sys.stderr)
            sys.exit(1)
        except:
            print('Error, quitting.', file=sys.stderr)
            traceback.print_exc()
            sys.exit(1)

    def _build_query(self, args):
        '''
        (self, argparse.Namespace) -> None
        Build a JSON query for commonly used ES DSL actions
        '''
        # retrieve command line arguments
        host = args.host
        index = args.index
        action = args.action
        size = args.size
        terms = args.terms
        arange = args.range
        fields = args.fields
        query = args.query
        count_flag = args.count

        # build URI query modifiers
        modifiers = ''
        if count_flag:
            modifiers = '?search_type=count'

        # build body of elasticsearch DSL query
        dsl_final = {}
        if query != None:
            # uses raw json query if provided
            self._query = json.loads(query)
        else:
            # builds stock queries from commandline args
            if action == None:          # argparse workaround, allows default
                action = 'stringquery'  # in mutually exclusive querygroup
            if action == 'stringquery':
                dsl_query = {'query': {'query_string': {'query': terms[0]}}}
            elif action == 'termquery':
                if terms[0].find(':') != -1:  # find() returns -1 on fail
                    dsl_query = {'query': {'term': {terms[0].split(':')[0]: \
                                          terms[0].split(':')[1]}}}
                else:
                    print('Argument TERMS must be in format TERM:VALUE')
                    sys.exit(1)
            elif action == 'termsagg':
                dsl_query = {'aggs': {'types': {'terms': {'field': terms[0]}}}}
                self._agg = True
            # build and add filter to query if used
            if arange != None:
                dsl_temp = {}
                dsl_filter = {'filter': {'range': {arange[0]: \
                                {'gte': arange[1], 'lte': arange[2]}}}}
                dsl_query.update(dsl_filter)
                dsl_temp['filtered'] = dsl_query
                dsl_query = dsl_temp
                # wrap with query tag
                dsl_final['query'] = dsl_query
            else:
                dsl_final = dsl_query
            # add _source fields filter if used
            if fields != None:
                dsl_source = {'_source': {'include': fields}}
                dsl_final.update(dsl_source)
            # add size parameter if used
            if size != None:
                dsl_size = {}
                dsl_size['size'] = size
                dsl_final.update(dsl_size)
            # store query to object
            self._query = dsl_final

        ### DEBUG CODE - uncomment to view generated query ############
        #print('http://' + host + ':' + esconstants.ES_PORT + '/' + index +
        #      '/' + '_search' + modifiers + ' -d ' + json.dumps(self._query))

        url = ('http://' + host + ':' + esconstants.ES_PORT + '/' + index +
               '/' + '_search' + modifiers)
        return url

    def _print_indices(self, response):
            sys.stdout.write(response.content.decode('UTF-8'))


class Parser(argparse.ArgumentParser):
    '''
    Modifies default behaviour of ArgumentParser to display usage on error.
    Remove this class and replace with argparse.ArgumentParser if running the
    script with no arguments is desirable
    '''
    def error(self, message):
        '''
        (self, string) -> None
        Initialization for error behaviour
        '''
        sys.stderr.write('usage: %s\n' % message)
        self.print_help()
        sys.exit(1)


def _prep_argparse():
    '''
    (None) -> None
    Example command line arguments for argparse. Note that argparse provides
    a default -h | --help option.
    See https://docs.python.org/2/howto/argparse.html for more.
    '''
    parser = Parser(description='esquery 0.1')
    # mutually exclusive argument group - provide either an action or raw query
    querygroup = parser.add_mutually_exclusive_group(required=True)
    querygroup.add_argument('-a', '--action', help='actions wrap common '
                            + 'query types (default:stringquery) - mutually ' +
                            'exclusive of --query', nargs='?',
                            choices=['stringquery', 'termquery', 'termsagg',
                            'count'], default='stringquery')
    querygroup.add_argument('-q', '--query', help='raw elasticsearch json ' +
                            'query')
    # mutually exclusive argument group - term is excluded from list request
    listgroup = parser.add_mutually_exclusive_group(required=True)
    listgroup.add_argument('-l', '--list', help='display available indices ' +
                           '- mutually exclusive of --terms',
                           action='store_true')
    listgroup.add_argument('-t', '--terms', help='some text to query - ' +
                           'format for stringquery is STRING, format for ' +
                           'termquery is TERM:STRING, format for termsagg ' +
                           'is TERM', nargs=1)
    # optional arguments
    parser.add_argument('-d', '--host', help='the elasticsearch host IP ' +
                        '(default: localhost)', nargs='?', default='127.0.0.1')
    parser.add_argument('-i', '--index', help='specifies a specific index ' +
                        'to query (default:all)', nargs='?',
                        default='logstash*')
    parser.add_argument('-s', '--size', help='number of hits to return ' +
                        '(default: 10)', nargs='?')
    parser.add_argument('-r', '--range', help='range filter, specify ' +
                        'field then beginning and end points as numeric ' +
                        'arguments or in YYYY-MM-DD format for dates eg; ' +
                        '--range severity 5 9 or -r timestamp 2015-03-05 ' +
                        '2015-03-11', nargs=3)
    parser.add_argument('-f', '--fields', help='specify source fields to ' +
                        'include in search (default:all fields)', nargs='+')
    parser.add_argument('-c', '--count', help='return a count of hits only',
                           action='store_true')
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    '''
    This is the first method run when called from the command line
    '''
    # prepare command line parser
    args = _prep_argparse()

    # perform elasticsearch query
    query = ESQuery()

    print(args)

    query.post(args)
    response = query.response

    # print response output to console
    if query._json:
        print(json.dumps(response.json(), sort_keys=True, indent=4))
