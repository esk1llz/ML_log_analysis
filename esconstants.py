#!/usr/bin/env python3

#
# esconstants.py - a namespace containing constants
# used throughout the project's classes
#
# File 6/6 - 'esconstants.py'
# See also 'escontrol.py'
# See also 'esquery.py'
# See also 'esvectorize.py'
# See also 'esanalyze.py'
# See also 'esindex.py'
#

# Version:    1.0
# Created:    2015-03-25
# Revision:   yyyy-mm-dd
# Revised by: First Last

# local timezone
TIMEZONE = 'US/Eastern'

# pick day for test data - how many days ago
TEST_DAY = 1

# network environment config
ES_HOST = '192.168.10.89'
ES_PORT = '9200'

# elasticsearch constants
ES_QUERY_SIZE = 10000
ES_INDEX_PREFIX = 'logstash-'
KEY_ES_SEARCH = 'hits'
KEY_ES_SOURCE = '_source'
KEY_ES_ID = '_id'
KEY_ES_TYPE = 'type'
KEY_ES_TOTAL = 'total'
KEY_ES_TIMESTAMP = '@timestamp'
KEY_OSSEC_TYPE = 'ossec'
KEY_OSSEC_RULE = 'rule_number'
KEY_SYSLOG_TYPE = 'syslog'
KEY_SYSLOG_SEV = 'syslog_severity_code'
KEY_SURICATA_TYPE = 'suricata'
KEY_SURICATA_EVENTS = 'event_type'
KEY_SURICATA_ALERT = 'alert'
KEY_SURICATA_SIG = 'signature_id'
TAG_OSSEC = 'ossec_outlier'
TAG_SYSLOG = 'syslog_outlier'
TAG_SURICATA = 'suricata_outlier'

# array size constants
NUM_DAYS = 31
NUM_BUCKETS = 25

# data cleaning tuning values
LOW_PC = 1
HIGH_PC = 99

# outlier detection tuning values
FFT_SHAPE_THRESHOLD = 0.5  # presently unused
FFT_ANALYSIS_DEPTH = 5
FFT_COMPONENT_WEIGHT = 2
# if the overall difference between test and train data
# is less than this percentage don't process it
FFT_TEST_DIFF_THRESHOLD = 0.5
# if a given point changes the metric more than this
# percentage mark it as an outlier
FFT_POINT_DIFF_THRESHOLD = 0.25
