#!/usr/bin/env python3

#
# esvectorize.py - normalizes elasticsearch queries for analysis
#
# File 3/6 - 'esvectorize.py'
# See also 'escontrol.py'
# See also 'esquery.py'
# See also 'esanalyze.py'
# See also 'esindex.py'
# See also 'esconstants.py'
#

# Version:    1.0
# Created:    2015-03-23
# Revision:   yyyy-mm-dd
# Revised by: First Last

import sys
import json
from datetime import *
import dateutil.parser
import pytz
from pytz import timezone
import argparse
import numpy

from esquery import ESQuery
import esconstants  # constants namespace


class ESVectorize(object):
    '''
    The vectorized results from an elasticsearch query on a single day
    and an associated rolling 30-day average of training data.

    Attributes:
        day_vecs: Structured test data ready for analysis
        grouped_vecs: Structured data for a <= 31 day period of logs
        _day_data: JSON data for a single day's logs
        _result_vectors: Working data for a single day as arrays
        _result_data: Temporary vectorizing workspace
        _LOGTYPE_MUNGE: A list of internal methods comprising a dispatch
                       table for operations on specific log types

    # PROBLEM For any given time period, we could select for either a
    # particular log type or all logs in the period. In either case, the
    # JSON returned is not flat (it contains nested lists and dicts) and
    # furthermore will vary in length as some log types have optional
    # fields for differing circumstances

    # SOLUTION: for each log type, for each event type
    # make counts by one hour time intervals and create a rolling
    # weekly average for hours by day of week. This will allow FFT analysis
    # and make determinations of difference in shape and amplitude possible
    # between the data sets.
    # OSSEC: count by hour of day by rule number
    # SURICATA: count _alerts_ by hour of day by signature id
    # SYSLOG: count by hour of day by severity code
    # POSTFIX: count by hour of day by program *will need to encode this
    '''
    def __init__(self, data, printflag=False):
        '''
        (self) -> ESNormalize
        Initializes a new ESNormalize object
        '''
        self.day_vecs = {}         # _day_data vectors ready for analysis
        self.grouped_vecs = {}     # rolling 30-day avg by day logtype, subtype
        self._day_data = data      # received day query in raw form
        self._result_vectors = {}  # vectorized results
        self._result_data = None   # workspace for vectorizing
        if printflag == True:      # print response for debug
            self._jsondump(self._day_data)
            self._fieldsdump(self._day_data)
        # static dispatch table for log normalization cases
        self._LOGTYPE_MUNGE = {'ossec': ESVectorize._munge_ossec,
                              'syslog': ESVectorize._munge_syslog,
                              'suricata': ESVectorize._munge_suricata}

    def get_day_vectors(self):
        '''
        (self) -> None
        Create a data structure containing vectors from yesterday
        '''
        temp_vecs = []
        # Monday = 0, Sunday = 6
        day = date.today().weekday() - 1
        day_vecs = {}
        day_vecs[day] = {}

        self._result_data = self._day_data
        self._count_day()

        temp_vecs.append(day)
        temp_vecs.append(self._result_vectors)
        # organize the structure by type and subtype
        self.day_vecs = self._organize_vectors(temp_vecs[1], day_vecs[day])

    def get_avg_vectors(self):
        '''
        (self) -> None
        Create a 30-day rolling average of log statistics to date
        '''
        month_vecs = []
        grouped_vecs = {}

        # create a list of 31 dates, starting the day before
        # yesterday since yesterday is the test data set
        dates = []
        dates.append(datetime.now(pytz.timezone(esconstants.TIMEZONE)) -
                timedelta(days=(esconstants.TEST_DAY + 1)))
        # Monday = 0, Sunday = 6
        dayofweek = (datetime.now(pytz.timezone(esconstants.TIMEZONE)) -
                     timedelta(days=(esconstants.TEST_DAY + 1))).weekday()
        for i in range(1, esconstants.NUM_DAYS):
            dates.append(dates[0] - timedelta(days=i))

        # create argument namespace for ESQuery
        args = argparse.Namespace()

        # perform elasticsearch query
        query = ESQuery()
        args.action = 'stringquery'
        args.count = False
        args.fields = None
        args.host = esconstants.ES_HOST
        args.index = 'logstash*'
        args.list = False
        args.query = None
        args.size = esconstants.ES_QUERY_SIZE
        args.terms = ['*']

        # get 30 day's worth of logs
        for adate in dates:
            # create date range for single day, pass to esquery
            args.range = [esconstants.KEY_ES_TIMESTAMP,\
                          str(adate.isoformat()[:10]),\
                          str(adate.isoformat()[:10])]
            query.post(args)
            result = query.response.json()
            # skip empty results
            if result[esconstants.KEY_ES_SEARCH][esconstants.KEY_ES_TOTAL] \
                      == 0:
                print('Dropped day: ' + str(adate.isoformat()[:10]))
                # decrement day
                dayofweek = (dayofweek - 1) % 7
                continue
            self._result_data = result
            self._count_day()
            # append day's results to month
            print('Got day: ' + str(adate.isoformat()[:10]))
            month_vecs.append(dayofweek)
            month_vecs.append(self._result_vectors)
            # decrement day
            dayofweek = (dayofweek - 1) % 7
        print()

        # generate a single array containing avg of each day in past 30
        # first we need to group all like vectors by day, type, subtype
        day = 0
        for i, elt in enumerate(month_vecs):
            # add days to structure, every other element of list is a day
            if i % 2 == 0:
                if elt in grouped_vecs:
                    day = elt
                    continue
                else:
                    day = elt
                    grouped_vecs[elt] = {}
            else:
                # organize the structure by type and subtype
                grouped_vecs[day] = self._organize_vectors(elt,
                        grouped_vecs[day])
        # calculate average scalars by day, type, subtype
        for day in grouped_vecs.keys():
            for type_key in grouped_vecs[day].keys():
                for subtype in grouped_vecs[day][type_key].keys():
                    # if only one line don't average
                    if len(grouped_vecs[day][type_key][subtype].shape) == 1:
                        continue
                    else:
                        grouped_vecs[day][type_key][subtype] = \
                                numpy.average(grouped_vecs[day]
                                [type_key][subtype], axis=0)
        self.grouped_vecs = grouped_vecs

    def _organize_vectors(self, invecs, outdict):
        '''
        (self, dict, dict) -> dict
        Create a structured representation of counts by event type and subtype
        '''
        # add alert types to structure
        for type_key in invecs.keys():
            if type_key not in outdict.keys():
                outdict[type_key] = {}
            daytype_vectors = invecs[type_key]
            # add alert subtypes to structure
            alert_subtypes = self._get_subtypes(daytype_vectors)
            for subtype in alert_subtypes:
                if subtype not in outdict[type_key].keys():
                    outdict[type_key][subtype] = \
                            self._get_vector(daytype_vectors, subtype)
                # add vectors to arrays
                else:
                    arr = outdict[type_key][subtype]
                    vector = self._get_vector(daytype_vectors, subtype)
                    outdict[type_key][subtype] = \
                            numpy.vstack((arr, vector))
        return outdict

    def _get_subtypes(self, vectors):
        '''
        (self, Numpy.Array) -> list
        Returns a list of the subtypes/signature numbers available for
        an array of count results for a given signature type
        '''
        subtype_list = []
        for vector in vectors:
            # convert int to string so JSON can serialize it
            subtype_list.append(str(vector[24]))
        return subtype_list

    def _get_vector(self, vectors, subtype):
        '''
        (self, Numpy.Array, int) -> list
        Returns an array of count vectors available for a given day,
        alert type, and subtype
        '''
        for vector in vectors:
            if str(vector[24]) == subtype:
                subtyped_scalar = vector
                # shave off the last column of subtype numbers
                counts_scalar = numpy.delete(subtyped_scalar,
                                             esconstants.NUM_BUCKETS - 1)
                return counts_scalar

    def _count_day(self):
        '''
        (self) -> None
        Vectorize returned data for analysis
        '''
        hits_day = {}
        counts_day = {}

        # collate hits by log type
        hits_day = self._hits_by_key(self._result_data
                                    [esconstants.KEY_ES_SEARCH]
                                    [esconstants.KEY_ES_SEARCH],
                                    esconstants.KEY_ES_TYPE)

        # generate vector of hourly hit counts for the day
        for logtype in hits_day.keys():
            hits_vec = []
            if logtype in self._LOGTYPE_MUNGE.keys():
                hits_vec = self._LOGTYPE_MUNGE[logtype](self, hits_day)
                # only add to dict if hits are returned (suricata)
                if hits_vec is not None:
                    counts_day[logtype] = hits_vec
        self._result_vectors = counts_day

    def _munge_ossec(self, hits):
        '''
        (self, dict) -> Numpy.array
        Processes list of ossec log key-value data and generates a
        vector array of hourly counts
        '''
        hits_rule = {}   # to store collection of hits by rule number
        hit_vecs = None  # numpy array of counting bins

        # collate events by rule_number
        hits_rule = self._hits_by_key(hits[esconstants.KEY_OSSEC_TYPE],
                                      esconstants.KEY_OSSEC_RULE)
        # count events by hourly buckets
        hit_vecs = self._hourly_counts(hits_rule)
        return hit_vecs

    def _munge_syslog(self, hits):
        '''
        (self, dict) -> Numpy.array
        Processes list of syslog log key-value data and generates a
        vector array of hourly counts
        '''
        hits_sev = {}   # to store collection of hits by severity
        hit_vecs = None  # numpy array of counting bins

        # collate events by rule_number
        hits_sev = self._hits_by_key(hits[esconstants.KEY_SYSLOG_TYPE],
                                     esconstants.KEY_SYSLOG_SEV)
        # count events by hourly buckets
        hit_vecs = self._hourly_counts(hits_sev)
        return hit_vecs

    def _munge_suricata(self, hits):
        '''
        (self, dict) -> Numpy.array
        Processes list of suricata log key-value data and generates a
        vector array of hourly counts
        '''
        hits_alert_sig = {}  # to store collection of hits by alert signature
        hit_vecs = None      # numpy array of counting bins
        alert_hits = []      # only alert hits

        # collect only suricata events with alerts by looking in event_type
        for hit in hits[esconstants.KEY_SURICATA_TYPE]:
            if esconstants.KEY_SURICATA_EVENTS in hit and \
                    hit[esconstants.KEY_SURICATA_EVENTS] == 'alert':
                alert_hits.append(hit)
            if len(alert_hits) == 0:
                return None
        hits[esconstants.KEY_SURICATA_TYPE] = alert_hits

        # collate events by signature number
        hits_sev = self._hits_by_key(hits[esconstants.KEY_SURICATA_TYPE],
                                     esconstants.KEY_SURICATA_SIG)
        # count events by hourly buckets
        hit_vecs = self._hourly_counts(hits_sev)
        return hit_vecs

    def _hits_by_key(self, source_list, key):
        '''
        (self, dict, string, string) -> dict
        Returns a nested dictionary of items selected on the
        chosen keys in a input dictionary
        '''
        hits_by_key = {}
        for hit in source_list:
            # unwrap fields from _source key if we haven't yet
            if esconstants.KEY_ES_SOURCE in hit:
                hit = hit[esconstants.KEY_ES_SOURCE]
            # we need to unwrap suricata alerts which are nested
            # two deep while saving the timestamp
            if key == esconstants.KEY_SURICATA_SIG:
                timestamp = hit.get(esconstants.KEY_ES_TIMESTAMP)
                hit = hit[esconstants.KEY_SURICATA_ALERT]
                hit[esconstants.KEY_ES_TIMESTAMP] = timestamp
            # categorize the hits by key
            if hit[key] in hits_by_key:
                hits_by_key[hit[key]] \
                            .append(hit)
            else:
                hits_by_key[hit[key]] = [hit]
        return hits_by_key

    def _hourly_counts(self, hits_type):
        '''
        (self, dict) -> Numpy.array
        Generates a vector array of hourly log event counts
        '''
        hit_vecs = None  # numpy array of counting bins

        # count by time buckets by ruletype
        rule_count = len(hits_type)
        hit_vecs = numpy.zeros((rule_count, esconstants.NUM_BUCKETS),
                               dtype=int)
        for i, atype in enumerate(hits_type):
            for hit in hits_type[atype]:
                timestamp = dateutil.parser.parse(hit[\
                        esconstants.KEY_ES_TIMESTAMP]).time()
                hour = timestamp.hour
                hit_vecs[i, hour] += 1
            hit_vecs[i, esconstants.NUM_BUCKETS - 1] = int(atype)
        return(hit_vecs)

    def _jsondump(self, data):
        '''
        (self) -> None
        Pretty-print json data
        '''
        # send results to STDOUT
        print(json.dumps(data, sort_keys=True, indent=4))

    def _fieldsdump(self, data):
        '''
        (self) -> None
        Print data in key: value format
        '''
        for i, elt in enumerate(data[esconstants.KEY_ES_SEARCH]
                                [esconstants.KEY_ES_SEARCH]):
            print('\n*** HIT #' + str(i + 1) + ' ****************************')
            for j in elt[esconstants.KEY_ES_SOURCE].items():
                print(str(j[0]).strip() + ': ' + str(j[1]).strip())
