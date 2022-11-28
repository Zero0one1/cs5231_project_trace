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

CHECK_CANARY_BYTECODE_PATTERN = [
    "48 8b 45 f8",  # mov  rax, qword ptr [rbp - 8]
    "64 48 33 04 25",  # xor  rax, qword ptr fs:[?]
    "74 05"  # je &addr of normal next step (fixed offset 0x05)
]
INIT_CANARY_BYTECODE_PATTERN = [
    "64 48 8b 04 25",  # mov  rax, qword ptr fs:[?]
    "48 89 45 f8",  # mov  qword ptr [rbp - 8], rax
    "31 c0"  # xor  eax, eax
]


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
            "^\[(?P<line_num>\d+)\]\s*(?P<addr>0x[0-9a-f]+):\s*(?P<bytecode>([0-9a-f]{2}\s)+)\s*(?P<op>[a-z]*)\s*(?P<args>.*)$",
            line
        )
        if res is not None:
            self.data[int(res.group('line_num'))] = {
                "address": res.group('addr'),
                "bytecode": res.group('bytecode'),
                "operation": res.group('op'),
                "arguments": res.group('args'),
            }

    def get(self, line_num):
        ''' return the execution on certain line'''
        return self.data[line_num]

    def size(self):
        ''' return the total number of lines contained in the trace'''
        return len(self.data)

def find_canary_check_inst(trace):
    '''return the line number of the instruction that crashes the canary'''
    for i in range(trace.size()-5, 0, -1):
        cur = trace.get(i)
        step_after = trace.get(i+1)
        two_step_after = trace.get(i+2)
        four_step_after = trace.get(i+4)

        if cur["bytecode"].startswith(CHECK_CANARY_BYTECODE_PATTERN[0]) and \
           step_after["bytecode"].startswith(CHECK_CANARY_BYTECODE_PATTERN[1]) and \
           two_step_after["bytecode"].startswith(CHECK_CANARY_BYTECODE_PATTERN[2]) and \
           four_step_after["arguments"].startswith("Capstone Error"):
            return i

def find_canary_init_inst(trace, canary_check_ln):
    '''
    given the respective line number of canary check
    return the line number of the nearest canary init instruction
    '''
    for i in range(canary_check_ln, 0, -1):
        cur = trace.get(i)
        step_after = trace.get(i+1)
        two_step_after = trace.get(i+2)

        if cur["bytecode"].startswith(INIT_CANARY_BYTECODE_PATTERN[0]) and \
           step_after["bytecode"].startswith(INIT_CANARY_BYTECODE_PATTERN[1]) and \
           two_step_after["bytecode"].startswith(INIT_CANARY_BYTECODE_PATTERN[2]):
            return i
#
# ==== Script Start =====
#


# Task 2: parse and store the address range of the binary from proc_mem
NORMAL_ADDR_RANGE = get_proc_mem_range(NORMAL_DIR + "/proc_map")
VULN_ADDR_RANGE = get_proc_mem_range(VULN_DIR + "/proc_map")

# Task 3.1: get the diff from two traces
normal_trace = ExecTrace(NORMAL_TRACE_FILE)
vuln_trace = ExecTrace(VULN_TRACE_FILE)

# Task 3.2: find line number for instruction that checks the canary
canary_check_ln = find_canary_check_inst(vuln_trace)
print("Canary check at Line " + str(canary_check_ln) + ":")
print("  " + str(vuln_trace.get(canary_check_ln)))

# Task 3.3: find line number for instruction that initializes the canary
canary_init_ln = find_canary_init_inst(vuln_trace, canary_check_ln)
print("Canary init at Line " + str(canary_init_ln) + ":")
print("  " + str(vuln_trace.get(canary_init_ln)))
# ==== Script End =====
