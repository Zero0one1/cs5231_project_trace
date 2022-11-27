import re

def locate_mem_copy_call(lines, end_idx):
    # The latest call instr must be the memcpy copy functions that overflow the canary.
    for idx, line in enumerate(reversed(lines[:end_idx])):
        if "call" in line:
            return end_idx - idx - 1

def locate_line_idx_by_instr_addr(lines: list, instr_addr: str):
    for idx, line in enumerate(lines):
        if instr_addr in line:
            return idx

def read_trace_file(path):
    with open(path, "r") as f:
        return f.readlines()

def extract_strcpy_args(lines, strcpy_idx):
    try:
        lea_buf_line = lines[strcpy_idx - 3]
        res = re.findall(r'lea.+\[rbp - (0x\d+)\]', lea_buf_line)
        if not res:
            print("""[ERROR] cannot find the arguments of strcpy.  
            Note: we can only detect overflow caused by strcpy().
            Set buf_size to 0.""")
        else:
            offset = res[0] # hex string
            offset = int(offset, 16) # dec int
            buf_size = offset - 8 # canary is 8 bytes wide
    except:
        print("[ERROR] in extract_strcpy_args(). Set buf_size to 0.")
        buf_size = 0
    return buf_size

def main(path, instr_addr_w: str, instr_addr_r: str):
    ass_lines = read_trace_file(path)

    line_idx_addr_w = locate_line_idx_by_instr_addr(ass_lines, instr_addr_w)
    line_idx_addr_r = locate_line_idx_by_instr_addr(ass_lines, instr_addr_r)

    line_idx_mem_copy_call = locate_mem_copy_call(ass_lines, line_idx_addr_r)

    buf_size = extract_strcpy_args(ass_lines, line_idx_mem_copy_call)
    print(f"[INFO] Buffer size is {buf_size} in decimal")


if __name__ == "__main__":
    trace_s_path = "../data/6555.all"
    instr_addr_set_canary, instr_addr_chk_canary = "0x7f81b913f199", "0x7f81b913f1c0"
    main(trace_s_path, instr_addr_set_canary, instr_addr_chk_canary)