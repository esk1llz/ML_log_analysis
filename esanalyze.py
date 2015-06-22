#!/usr/bin/env python3

#
# esanalyze.py - analyzes elasticsearch queries for outliers
#
# File 4/6 - 'esanalyze.py'
# See also 'escontrol.py'
# See also 'esquery.py'
# See also 'esvectorize.py'
# See also 'esindex.py'
# See also 'esconstants.py'
#

# Version:    1.0
# Created:    2015-03-25
# Revision:   yyyy-mm-dd
# Revised by: First Last

import numpy
from scipy import fftpack
import matplotlib.pyplot as plot

from datetime import *
import dateutil.parser
import pytz

import esconstants


class ESAnalyze(object):
    '''
    A set of counted statistics comparing the log events of a
    given time period (single day) with a 31-day set of training
    data by log type and subtype.

    Attributes:
        self.test_data: A sample to be tested for outliers
        self.outliers_flag: Flags if there are results in the object
        self.outliers: A dictionary of results
        self.test_data: The test dataset
        self._train_data: The baseline training dataset
        self._shape_flag: Indicates if the shape of the sets is similar
        self._amplitude_diff: A metric test v train differences in amplitude
        self._plot_flag: A flag to indicate if FFT plots should be displayed
    '''
    def __init__(self, testset, trainset, plot=False):
        self.test_date = None
        self.outliers_flag = False
        self.outliers = {}
        self.test_data = testset
        self._train_data = trainset
        self._shape_flag = False
        self._amplitude_diff = 0
        self._plot_flag = plot

    def data_clean(self):
        '''
        (self) -> None
        Smooth the training data by discarding extreme outliers
        '''
        agg_data = {}   # aggregate all the days together
        trim_data = {}  # percentile calculations for each subtype

        # discard days to create aggregated data
        for day in self._train_data.keys():
            # add alert types to structure
            for type_key in self._train_data[day].keys():
                if type_key not in agg_data.keys():
                    agg_data[type_key] = {}
                # add alert subtypes to structure
                for subtype in self._train_data[day][type_key]:
                    if subtype not in agg_data[type_key].keys():
                        agg_data[type_key][subtype] = {}
                    # add vectors to arrays
                    arr = agg_data[type_key][subtype]
                    vector = self._train_data[day][type_key][subtype]
                    if len(agg_data[type_key][subtype]) == 0:
                        agg_data[type_key][subtype] = vector
                    else:
                        agg_data[type_key][subtype] = \
                                numpy.vstack((arr, vector))
        # create average scalars of the aggregate data by type, subtype
        for type_key in agg_data.keys():
            if type_key not in trim_data.keys():
                    trim_data[type_key] = {}
            for subtype in agg_data[type_key].keys():
                if subtype not in trim_data[type_key].keys():
                    trim_data[type_key][subtype] = {}
                # if only one line don't average
                if len(agg_data[type_key][subtype].shape) == 1:
                    trim_data[type_key][subtype] = \
                            agg_data[type_key][subtype]
                # if greater than one line in array, calculate average
                else:
                    agg_data[type_key][subtype] = \
                            numpy.average(agg_data[type_key][subtype],
                                          axis=0)
                # calculate 1st and 99th percentiles - or whatever is
                # set in esconstants
                trim_data[type_key][subtype] = \
                        numpy.percentile(agg_data[type_key][subtype],
                                [esconstants.LOW_PC, esconstants.HIGH_PC])
        # one final loop over the training data to give it a haircut
        for day in self._train_data.keys():
            for type_key in self._train_data[day].keys():
                for subtype in self._train_data[day][type_key]:
                    for i in range(len(self._train_data[day]
                                       [type_key][subtype])):
                        if self._train_data[day][type_key][subtype][i] < \
                                trim_data[type_key][subtype][0]:
                            self._train_data[day][type_key][subtype][i] = \
                                    trim_data[type_key][subtype][0]
                        elif self._train_data[day][type_key][subtype][i] > \
                                trim_data[type_key][subtype][1]:
                            self._train_data[day][type_key][subtype][i] = \
                                    trim_data[type_key][subtype][1]

    def outlier_detection(self):
        '''
        (self) -> None
        Loop over the test set and compare it to available averages
        by type and subtype
        '''
        self.test_date = datetime.now(pytz.timezone(esconstants.TIMEZONE)) -\
                timedelta(days=(esconstants.TEST_DAY))
        day = self.test_date.weekday()
        test = self.test_data
        train = self._train_data
        outlier_positions = []
        self._shape_flag = False
        self.outliers_flag = False
        self.outliers = {}

        # perform detection for each subtype by type in test set
        for type_key in self.test_data.keys():
            for subtype in self.test_data[type_key]:
                # initialize array to hold positions of discovered outliers
                outlier_positions = []

                try:
                    # compute FFT for comparing test and train arrays
                    testfft = fftpack.fft(test[type_key][subtype])
                    trainfft = fftpack.fft(train[day][type_key][subtype])
                    self._amplitude_diff = self._fft_amplitude_diff(testfft,
                                                                    trainfft)
                    # outliers check 1 - is overall difference between test
                    # and train data greater than threshold? if not skip it
                    if self._amplitude_diff < \
                            esconstants.FFT_TEST_DIFF_THRESHOLD:
                        continue
                    # outliers check 2 - see if each observation in test set
                    # is an outlier by swapping it out with training data and
                    # noting change in overall difference
                    for i in range(esconstants.NUM_BUCKETS - 1):
                        test_tmp = numpy.copy(test[type_key][subtype])
                        test_tmp = test_tmp.astype(numpy.float64, copy=False)
                        test_tmp[i] = train[day][type_key][subtype][i]
                        outlierfft = fftpack.fft(test_tmp)
                        #norm_corr = numpy.corrcoef(outlierfft, trainfft)
                        #if norm_corr[0, 1] > esconstants.FFT_SHAPE_THRESHOLD:
                        #    self._shape_flag = True
                        difference = self._fft_amplitude_diff(outlierfft,
                                                              trainfft)
                        # change below to abs if you want to account for the
                        # difference caused by test data having FEWER alerts
                        if (self._amplitude_diff - difference) / \
                                self._amplitude_diff > \
                                esconstants.FFT_POINT_DIFF_THRESHOLD:
                            outlier_positions.append(i)

                            print('ALERT on test data:')
                            print(self.test_data[type_key][subtype])
                            print('vs training data')
                            print(self._train_data[day][type_key][subtype])
                            print('For logtype ' + str(type_key) +
                                  ', subtype ' + str(subtype) + ' for date ' +
                                  (datetime.now(pytz.timezone(
                                  esconstants.TIMEZONE)) -
                                  timedelta(days=(esconstants.TEST_DAY)))\
                                  .isoformat()[:10] + ', the value ' +\
                                  str(test[type_key][subtype][i]
                                    ) + ' at hour ' +
                                    str(i) + ' may be an outlier!')
                            print('Test/Train difference: ' +
                                  str(self._amplitude_diff))
                            print('Observation variance: ' +
                                  str((self._amplitude_diff - difference) / \
                                  self._amplitude_diff))
                            print()
                            if self._plot_flag == True:
                                self._plot(day, type_key, subtype)
                # hits without corresponding training data get special handling
                except KeyError as e:
                    print("WARNING Subtype {0} doesn't ".format(str(subtype)) +
                            'exist in training data for {0}'.format(e.args[0]))
                    print('*** Sending this as an alert to SIEM')
                    print()
                    self.outliers_flag = True
                    # get hour from location of alert in test data
                    for i in range(0, len(self.test_data[type_key][subtype])):
                        if self.test_data[type_key][subtype][i] >= 1:
                            outlier_positions.append(i)
                    # store hours with hits to outlier record
                    self._store_outlier_alerts(outlier_positions, type_key,
                                               subtype)
                    continue

                # send potential alerts to alert database
                if outlier_positions:
                    self.outliers_flag = True
                    self._store_outlier_alerts(outlier_positions, type_key,
                                               subtype)
        if not self.outliers_flag:
            print('No outliers detected for ' +
                                    str((datetime.now(pytz.timezone(
                                    esconstants.TIMEZONE)) -
                                    timedelta(days=(esconstants.TEST_DAY)))\
                                    .isoformat()[:10]))

    def _fft_amplitude_diff(self, test, train):
        '''
        (self, numpy.ndarray, numpy.ndarray) -> int
        Compare the amplitudes of two FFT arrays, return a difference metric
        '''
        freq_diffs = []
        # reduce weighting of each successive freq component geometrically
        freq_weight = esconstants.FFT_COMPONENT_WEIGHT
        curr_weight = 1
        for i in range(0, esconstants.FFT_ANALYSIS_DEPTH):
            freq_diffs.append(abs(abs(test[i]) - abs(train[i])) / curr_weight)
            curr_weight *= freq_weight
        difference = sum(freq_diffs) / esconstants.FFT_ANALYSIS_DEPTH / \
                abs(train[i])
        return difference

    def _store_outlier_alerts(self, outlier_positions, type_key, subtype):
        '''
        (self, list, string, string) -> None
        Insert new alerts into elasticsearch key store
        '''
        # add type_key to outlier record
        if type_key not in self.outliers.keys():
            self.outliers[type_key] = {}
        # add alert subtype to outlier_record
        if subtype not in self.outliers[type_key].keys():
            self.outliers[type_key][subtype] = {}
        # store list of outlier positions
        self.outliers[type_key][subtype] = outlier_positions

    def _fft_slow(self, x):
        '''
        (self, NDArray) -> NDArray
        Naively compute the Discrete Fourier Transform of the 1D array x
        Method demonstrates how FFT works but use fast numpy function instead
        '''
        x = numpy.asarray(x, dtype=float)
        N = x.shape[0]
        n = numpy.arange(N)
        k = n.reshape((N, 1))
        M = numpy.exp(-2j * numpy.pi * k * n / N)
        return numpy.dot(M, x)

    def _plot(self, day, type_key, subtype):
        '''
        (self, int, string, string) -> None
        Plot the data containing an identified outlier
        '''
        graphs = []
        graphs.append(self.test_data[type_key][subtype])
        graphs.append(self._train_data[day][type_key][subtype])

        print('PLOT DATA')
        print('-----------------------------')
        print('Shape: ' + str(graphs[0].shape))
        print('-----------------------------')
        print(type_key, subtype)
        print('test:')
        print(self.test_data[type_key][subtype])
        print('test_fft:')
        print(fftpack.fft(self.test_data[type_key][subtype]))
        print('train:')
        print(self._train_data[day][type_key][subtype])
        print('train_fft:')
        print(fftpack.fft(self._train_data[day][type_key][subtype]))
        print()

        for g in graphs:
            t = numpy.linspace(1, 24, 24)
            G = fftpack.fft(g)           # FFT of g
            f = fftpack.fftfreq(g.size)  # frequencies f[i] of g[i]
            f = fftpack.fftshift(f)  # shift freqs from min to max
            G = fftpack.fftshift(G)  # shift G order to correspond to f

            fig = plot.figure(1,
                    figsize=(8, 6), frameon=False)
            ax1 = fig.add_subplot(211)
            ax1.plot(t, g)
            ax1.set_xlabel('t')
            ax1.set_ylabel('g(t)')

            ax2 = fig.add_subplot(212)
            ax2.plot(f, numpy.real(G), color='dodgerblue',
                     label='real part')
            ax2.plot(f, numpy.imag(G), color='coral',
                     label='imaginary part')
            ax2.legend()
            ax2.set_xlabel('f')
            ax2.set_ylabel('G(f)')

        plot.show()
