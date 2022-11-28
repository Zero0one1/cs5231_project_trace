#!/usr/bin/env python3

import sys
import getopt
import re
from collections import defaultdict

NORMAL_DIR = "../data/buffer_overflow-4756(normal_trace)/4756"
VULN_DIR = "../data/buffer_overflow-6555(vulnerable_trace)/6555"
BIN_FILE = "buffer_overflow"
NORMAL_ADDR_RANGE = (0, 0)
VULN_ADDR_RANGE = (0, 0)
NORMAL_TRACE_FILE = "../data/4756.all"
VULN_TRACE_FILE = "../data/6555.all"


def get_proc_mem_range(filename):
    '''
    input: proc_mem file path
    output: memory range of BIN_FILE as (lowest, highest)
    throw: if no memory is allocated (found) for BIN_FILE
    '''

    print("parsing: " + filename + "...")

    f = open(filename, "r")
    lowest = 0
    highest = 0

    for line in f:
        res = re.search(
                "^(?P<start>[0-9a-f]+)-(?P<end>[0-9a-f]+).*" + BIN_FILE, 
                line)
        if res is not None:
            start = int(res.group('start'), 16)
            end = int(res.group('end'), 16)
            lowest = start if lowest == 0 or start < lowest else lowest
            highest = end if end == 0 or end > highest else highest

    if lowest == 0 or highest == 0:
        raise Exception("potentially wrong binary file name")

    # print(hex(lowest), hex(highest))
    f.close()
    return (lowest, highest)


def is_in_range(addr, is_vuln):
    '''
    Check if addr is within the memory address range of the binary
    is_vuln indicates if this check is for the vulnerable execution
    '''
    if is_vuln:
        return VULN_ADDR_RANGE[0] <= addr and addr <= VULN_ADDR_RANGE[1]
    else:
        return NORMAL_ADDR_RANGE[0] <= addr and addr <= NORMAL_ADDR_RANGE[1]


class ExecTrace:
    '''
    A struct holding an execution trace
    '''

    def __init__(self, filename):
        '''create an instance from an execution trace file'''
        f = open(filename, "r")
        self.data = defaultdict(dict)

        for line in f:
            self.__add_trace_line(line)

        f.close()

    def __add_trace_line(self, line):
        # can test with https://regex101.com/r/2paWA6/1
        res = re.search(
            "^\[(?P<line_num>\d+)\]\s*(?P<addr>0x[0-9a-f]+):\s*(?P<bytecode>([0-9a-f]{2}\s)+)\s*(?P<inst>.*)$",
            line
        )
        if res is not None:
            self.data[int(res.group('line_num'))] = {
                "address": res.group('addr'),
                "bytecode": res.group('bytecode'),
                "instruction": res.group('inst')
            }

    def get(self, line_num):
        ''' return the execution on certain line'''
        return self.data[line_num]

    def size(self):
        ''' return the total number of lines contained in the trace'''
        return len(self.data)

#
# ==== Script Start =====
#


# Task 2: parse and store the address range of the binary from proc_mem
NORMAL_ADDR_RANGE = get_proc_mem_range(NORMAL_DIR + "/proc_map")
VULN_ADDR_RANGE = get_proc_mem_range(VULN_DIR + "/proc_map")

# Task 3.1: get the diff from two traces
normal_trace = ExecTrace(NORMAL_TRACE_FILE)
vuln_trace = ExecTrace(VULN_TRACE_FILE)
diff_trace = []

for i in range(1, min(normal_trace.size(), vuln_trace.size())):
    n = normal_trace.get(i)
    v = vuln_trace.get(i)
    if n["bytecode"] != v["bytecode"]:
        diff_trace.append({"line": i, "normal": n, "vuln": v})

print(diff_trace[0:3])
# ==== Script End =====
