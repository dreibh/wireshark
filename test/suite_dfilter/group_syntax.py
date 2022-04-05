# Copyright (c) 2013 by Gilbert Ramirez <gram@alumni.rice.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import unittest
import fixtures
from suite_dfilter.dfiltertest import *


@fixtures.uses_fixtures
class case_syntax(unittest.TestCase):
    trace_file = "http.pcap"

    def test_exists_1(self, checkDFilterCount):
        dfilter = "frame"
        checkDFilterCount(dfilter, 1)

    def test_commute_1(self, checkDFilterCount):
        dfilter = "ip.proto == 6"
        checkDFilterCount(dfilter, 1)

    def test_commute_2(self, checkDFilterFail):
        dfilter = "6 == ip.proto"
        error = "Left side of \"==\" expression must be a field or function"
        checkDFilterFail(dfilter, error)

    def test_func_1(self, checkDFilterCount):
        dfilter = "len(frame) == 207"
        checkDFilterCount(dfilter, 1)

    def test_value_string_1(self, checkDFilterSucceed):
        dfilter = 'eth.fcs.status=="Bad"'
        checkDFilterSucceed(dfilter)

    def test_matches_1(self, checkDFilterSucceed):
        dfilter = 'http.request.method matches "^HEAD"'
        checkDFilterSucceed(dfilter)

    def test_matches_2(self, checkDFilterFail):
        dfilter = 'http.request.method matches HEAD'
        checkDFilterFail(dfilter, 'requires a double quoted string')

    def test_matches_3(self, checkDFilterFail):
        dfilter = 'http.request.method matches "^HEAD" matches "^POST"'
        checkDFilterFail(dfilter, '"matches" was unexpected in this context.')

    def test_matches_4(self, checkDFilterCount):
        dfilter = r'http.host matches r"update\.microsoft\.c.."'
        checkDFilterCount(dfilter, 1)

    def test_equal_1(self, checkDFilterCount):
        dfilter = 'ip.addr == 10.0.0.5'
        checkDFilterCount(dfilter, 1)

    def test_equal_2(self, checkDFilterCount):
        dfilter = 'ip.addr == 207.46.134.94'
        checkDFilterCount(dfilter, 1)

    def test_equal_3(self, checkDFilterCount):
        dfilter = 'ip.addr == 10.0.0.5 or ip.addr == 207.46.134.94'
        checkDFilterCount(dfilter, 1)

    def test_equal_4(self, checkDFilterCount):
        dfilter = 'ip.addr == 10.0.0.5 and ip.addr == 207.46.134.94'
        checkDFilterCount(dfilter, 1)

    def test_not_equal_1(self, checkDFilterCount):
        dfilter = 'ip.addr != 10.0.0.5'
        checkDFilterCount(dfilter, 0)

    def test_not_equal_2(self, checkDFilterCount):
        dfilter = 'ip.addr != 207.46.134.94'
        checkDFilterCount(dfilter, 0)

    def test_not_equal_3(self, checkDFilterCount):
        dfilter = 'ip.addr != 10.0.0.5 and ip.addr != 207.46.134.94'
        checkDFilterCount(dfilter, 0)

    def test_not_equal_4(self, checkDFilterCount):
        dfilter = 'ip.addr != 10.0.0.5 or ip.addr != 207.46.134.94'
        checkDFilterCount(dfilter, 0)

    def test_deprecated_1(self, checkDFilterSucceed):
        dfilter = "bootp"
        checkDFilterSucceed(dfilter, "Deprecated tokens: \"bootp\"")

    def test_charconst_bytes_1(self, checkDFilterCount):
        # Bytes as a character constant.
        dfilter = "frame contains 'H'"
        checkDFilterCount(dfilter, 1)

    def test_charconst_bytes_2(self, checkDFilterCount):
        dfilter = "frame[54] == 'H'"
        checkDFilterCount(dfilter, 1)

    def test_charconst_invalid(self, checkDFilterFail):
        dfilter = r"ip.proto == '\Z'"
        checkDFilterFail(dfilter, "isn't a valid character constant")

    def test_bool_1(self, checkDFilterCount):
        dfilter = "tcp.flags.push == 1"
        checkDFilterCount(dfilter, 1)

    def test_bool_2(self, checkDFilterCount):
        dfilter = "tcp.flags.push == true"
        checkDFilterCount(dfilter, 1)

@fixtures.uses_fixtures
class case_equality(unittest.TestCase):
    trace_file = "sip.pcapng"

    def test_all_eq_1(self, checkDFilterCount):
        dfilter = "udp.port === 5060"
        checkDFilterCount(dfilter, 2)

    def test_any_ne_1(self, checkDFilterCount):
        dfilter = "udp.port !== 5060"
        checkDFilterCount(dfilter, 4)

    def test_any_eq_1(self, checkDFilterCount):
        dfilter = "udp.port == 5060"
        checkDFilterCount(dfilter, 5)

    def test_all_ne_1(self, checkDFilterCount):
        dfilter = "udp.port != 5060"
        checkDFilterCount(dfilter, 1)

    def test_root_1(self, checkDFilterCount):
        dfilter = "udp.srcport == .udp.dstport"
        checkDFilterCount(dfilter, 2)

    def test_literal_1(self, checkDFilterCount):
        dfilter = "udp.port == :5070"
        checkDFilterCount(dfilter, 3)

    def test_literal_2(self, checkDFilterCount):
        dfilter = "udp contains <ce:13>"
        checkDFilterCount(dfilter, 1)

@fixtures.uses_fixtures
class case_bitwise(unittest.TestCase):
    trace_file = "http.pcap"

    def test_exists_1(self, checkDFilterCount):
        dfilter = "tcp.flags & 0x8"
        checkDFilterCount(dfilter, 1)

    def test_exists_2(self, checkDFilterCount):
        dfilter = "eth[0] & 1"
        checkDFilterCount(dfilter, 0)

    def test_equal_1(self, checkDFilterCount):
        dfilter = "tcp.flags & 0x0F == 8"
        checkDFilterCount(dfilter, 1)

    def test_equal_2(self, checkDFilterCount):
        dfilter = "tcp.srcport != tcp.dstport & 0x0F"
        checkDFilterCount(dfilter, 1)

@fixtures.uses_fixtures
class case_unary_minus(unittest.TestCase):
    trace_file = "http.pcap"

    def test_minus_const_1(self, checkDFilterCount):
        dfilter = "tcp.window_size_scalefactor == -1"
        checkDFilterCount(dfilter, 1)

    def test_minus_const_2(self, checkDFilterCount):
        dfilter = "tcp.window_size_scalefactor == -2"
        checkDFilterCount(dfilter, 0)

    def test_plus_const_1(self, checkDFilterCount):
        dfilter = "tcp.window_size_scalefactor == +1"
        checkDFilterCount(dfilter, 0)

    def test_unary_1(self, checkDFilterCount):
        dfilter = "tcp.window_size_scalefactor == -tcp.dstport"
        checkDFilterCount(dfilter, 0)

    def test_unary_2(self, checkDFilterCount):
        dfilter = "tcp.window_size_scalefactor == +tcp.dstport"
        checkDFilterCount(dfilter, 0)

    def test_unary_3(self, checkDFilterFail):
        error = 'Constant arithmetic expression on the LHS is invalid'
        dfilter = "-2 == tcp.dstport"
        checkDFilterFail(dfilter, error)

@fixtures.uses_fixtures
class case_arithmetic(unittest.TestCase):
    trace_file = "dhcp.pcap"

    def test_add_1(self, checkDFilterCount):
        dfilter = "udp.dstport == udp.srcport + 1"
        checkDFilterCount(dfilter, 2)

    def test_add_2(self, checkDFilterCount):
        dfilter = "udp.dstport == 66 + 1"
        checkDFilterCount(dfilter, 2)

    def test_add_3(self, checkDFilterCount):
        dfilter = "udp.dstport == 66+1"
        checkDFilterCount(dfilter, 2)

    def test_add_3(self, checkDFilterFail):
        error = 'Constant arithmetic expression on the LHS is invalid'
        dfilter = "2 + 3 == frame.number"
        checkDFilterFail(dfilter, error)

    def test_sub_1(self, checkDFilterCount):
        dfilter = "udp.srcport == udp.dstport - 1"
        checkDFilterCount(dfilter, 2)

    def test_sub_2(self, checkDFilterCount):
        dfilter = "udp.dstport == 68 - 1"
        checkDFilterCount(dfilter, 2)

    def test_sub_3(self, checkDFilterFail):
        # Minus operator requires spaces around it.
        error = '"68-1" is not a valid number.'
        dfilter = "udp.dstport == 68-1"
        checkDFilterFail(dfilter, error)

    def test_sub_4(self, checkDFilterCount):
        dfilter = "udp.length == ip.len - 20"
        checkDFilterCount(dfilter, 4)
