#!/usr/bin/env python3

import sys
import getopt
import re

NORMAL_DIR = ""
VULN_DIR = ""
BIN_FILE = "buffer_overflow"
NORMAL_ADDR_RANGE = (0, 0)
VULN_ADDR_RANGE = (0, 0)


def print_help():
    '''
    Print help message on how to use this python script
    '''
    print("""
        Usage: task3.py NORMAL_DIR VULNERABLE_DIR [OPTIONS]
        Options:
            -e, --example <folder>  An example of option
        """)
    sys.exit(0)


def cli():
    '''
    Entry point of CLI
    '''
    argv = sys.argv[1:]
    try:
        opts, args = getopt.getopt(argv, "n:v:", ["normal =", "vuln ="])
    except ValueError:
        print_help()

    for opt, arg in opts:
        if opt in ["-e", "--example"]:
            print("example opt, input arg: " + arg)
            print_help()
        else:
            print_help()

    if len(argv) < 2:
        print_help()

    global NORMAL_DIR, VULN_DIR
    NORMAL_DIR = argv[0]
    VULN_DIR = argv[1]

def get_proc_mem_range(f):
    '''
    input: proc_mem file path
    output: memory range of BIN_FILE as (lowest, highest)
    throw: if no memory is allocated (found) for BIN_FILE
    '''

    print("parsing: " + f.name + "...")

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

#
# ==== Script Start =====
#


cli()
# task 2: parse and store the address range of the binary from proc_mem
with open(NORMAL_DIR + "/proc_map", "r") as f:
    NORMAL_ADDR_RANGE = get_proc_mem_range(f)
with open(VULN_DIR + "/proc_map", "r") as f:
    VULN_ADDR_RANGE = get_proc_mem_range(f)

# ==== Script End =====
