#!/usr/bin/env python3

#
# escontrol.py - creates elasticsearch queries and handles analysis classes
#                to see if network traffic outliers exist for a given sample
#
# File 1/6 - 'escontrol.py'
# See also 'esquery.py'
# See also 'esvectorize.py'
# See also 'esanalyze.py'
# See also 'esindex.py'
# See also 'esconstants.py'
#
# usage: escontrol.py
#

# Version:    1.0
# Created:    2015-03-24
# Revision:   yyyy-mm-dd
# Revised by: First Last

import argparse
from datetime import *
import json

from esquery import ESQuery
from esvectorize import ESVectorize
from esanalyze import ESAnalyze
from esindex import ESIndex
import esconstants

if __name__ == '__main__':
    '''
    This is the first method run when called from the command line
    '''

    # we want the first available FULL day of logs, yesterday
    # or whichever day
    day = date.today() - timedelta(days=esconstants.TEST_DAY)

    # prepare command line parser
    args = argparse.Namespace()

    args.action = 'stringquery'
    args.count = False
    args.fields = None
    args.host = esconstants.ES_HOST
    args.index = 'logstash*'
    args.list = False
    args.query = None
    args.range = [esconstants.KEY_ES_TIMESTAMP, str(day), str(day)]
    # get all the things
    args.size = 1000000
    args.terms = ['*']

    # perform elasticsearch query
    query = ESQuery()
    query.post(args)
    response = query.response

    # stuff data in normalization class
    r = response.json()
    # load vectorize object with day's results
    day = ESVectorize(r)
    # obtain vectors for the day and training data
    day.get_day_vectors()
    day.get_avg_vectors()

    # now analyze and compare
    result = ESAnalyze(day.day_vecs, day.grouped_vecs, plot=False)
    result.data_clean()
    result.outlier_detection()

    # send any results to elasticsearch for display and print JSON
    # traffic to console
    if result.outliers_flag:
        print('OUTLIER RESULTS found for ' +\
              str(result.test_date.isoformat()[:10]) +\
              ' by type, subtype in the following hours:')
        print(result.outliers)
        print()

        # reindex and update outlying records
        shipper = ESIndex(result.test_date, result.outliers)
        shipper.index()

        print('Results of reindexing outlying records')
        print('--------------------------------------')
        i = 0
        for type_key in shipper.records.keys():
            for subtype in shipper.records[type_key].keys():
                for record in shipper.records[type_key][subtype]:
                    i += 1
        print('A total of ' + str(i) + ' records were updated and saved' +\
              ' as file \'records' + str(result.test_date.isoformat()[:10]) +\
              '\'')
        # save records to file in json format
        try:
            with open('records' + str(result.test_date.isoformat()[:10]),
                      'w') as file:
                json.dump(shipper.records, file)
        except:
            print('[!] Error saving records file')
