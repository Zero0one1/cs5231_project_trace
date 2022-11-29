import re

def locate_mem_copy_call(lines: list, start_idx: int, end_idx: int):
    """Locate all the "call xx" instructions between two given lines

    Args:
        lines (list): Lines of the whole file
        start_idx (int): Index of the file line from 0 to len(lines)-1
        end_idx (int): Index of the file line from 0 to len(lines)-1

    Returns:
        list: Indexes of the call instructions
    """
    res = list()
    for idx, line in enumerate(lines[start_idx:end_idx]):
        if "call" in line:
            res.append(start_idx + idx)
    return res

def locate_line_idx_by_instr_addr(lines: list, instr_addr: str) -> int:
    """Locate the line index of one instruction address

    Args:
        lines (list): Lines of the whole file
        instr_addr (str): one instruction address

    Returns:
        int: line index
    """
    for idx, line in enumerate(lines):
        if instr_addr in line:
            return idx

def read_trace_file(path: str) -> list:
    with open(path, "r") as f:
        return f.readlines()

def chk_call_func(lines: list, call_idx: int):
    """Check which sensitive APIs are called according to the instructions before the `call_idx` instruction.

    Args:
        lines (list): Lines of the whole file
        call_idx (int): Index of the file line of "call xx"

    Raises:
        Exception: if cannot find the arguments of called APIs

    Returns:
        int, int, int: destination and source buffer size (if found) and [line number]. Otherwise, 0, 0, 0.
    """
    if call_idx < 10:
        raise Exception("[ERROR] Invalid call instruction position (its index is too small)")

    dest, src, dest_line = 0, 0, 0

    # strcpy(dest, src)
    if "mov	rdi, rax" in lines[call_idx - 1] and "mov	rsi, rdx" in lines[call_idx - 2] and\
        re.search(r"lea	rax, qword ptr \[rbp - 0x[\da-f]+\]", lines[call_idx - 3]) and\
        re.search(r"mov	rdx, qword ptr \[rbp - 0x[\da-f]+\]", lines[call_idx - 4]):

        dest_buf_line, src_buf_line = lines[call_idx - 3], lines[call_idx - 4]
        dest = re.findall(r'lea.+\[rbp - (0x[\da-f]+)\]', dest_buf_line)
        src = re.findall(r'mov.+\[rbp - (0x[\da-f]+)\]', src_buf_line)
        if not src or not dest:
            raise Exception("[ERROR] cannot find the arguments of strcpy from the instructions.")
        dest = int(dest[0], 16) - 8 # change hex string to dec int and subtract 8 bytes of the canary
        src = int(src[0], 16) # temporarily use this
        dest_line = int(dest_buf_line.split()[0][1:-1]) # from [12345] to integer 12345
    # strcat, scanf, gets, memcpy, sprintf ... (strncpy, snprintf when used incorrectly)
    return dest, src, dest_line

def extract_strcpy_args(lines: list, blocks: list, call_idxs: list):
    """Check if the given call instructions are sensitive APIs. If they are, extract the size of their buffer (dest and src)

    Args:
        lines (list): Lines of the whole file
        blocks 
        call_idxs (list): List of call instructions' index

    Raises:
        Exception: if cannot find the called sensitive APIs

    Returns:
        _type_: _description_
    """

    dest_size_l, src_size_l, dest_line_l = list(), list(), list()

    # find the size of dest and src buffers of different APIs
    for call_idx in call_idxs:
        dest, src, dest_line = chk_call_func(lines, call_idx)
        if dest != 0 and src != 0:
            dest_size_l.append(dest)
            src_size_l.append(src)
            dest_line_l.append(dest_line)

    # find the potential addresses of dest buf (temporarily for strcpy()'s rax)
    dest_buf_addr = list()
    for idx, dest_line in enumerate(dest_line_l):
        block = blocks[dest_line + 1]
        if not block.startswith(str(dest_line + 1)):
            print(f"[WARNING] Cannot find {idx} buffer address")
            dest_buf_addr.append("")
        else:
            rax = re.findall(r"rax: ([\d+a-f]+)", block)
            if not rax:
                print(f"[WARNING] Cannot find {idx} buffer address")
                dest_buf_addr.append("")
            else:
                dest_buf_addr.append("0x"+rax[0])

    if len(dest_size_l) == 0:
        raise Exception("[ERROR] cannot find the called sensitive APIs")
    elif len(dest_size_l) == 1:
        print(f"[INFO] User input is larger than {dest_size_l[0]} bytes so that overflow happens.")
        print(f"Buffer size is possibly {dest_size_l[0]} bytes in decimal.")
        print(f"The overflowed buffer is at {dest_buf_addr[0]}.")
        return dest_size_l
    else:
        print(f"[WARNING] More than one sensitive APIs detected.\n")
        print("[INFO] Unsafe buffer sizes are possibly (bytes in decimal):", ", ".join([str(i) for i in dest_size_l]))
        print("These overflowed buffers are at", ", ".join(dest_buf_addr))
        return dest_size_l

def main(path, path_v, instr_addr_w: str, instr_addr_r: str):
    ass_lines = read_trace_file(path)
    with open(path_v, "r") as f:
        ass_v_blocks = f.read().split("\n[")
        # print(len(ass_v_blocks))
        # print(ass_v_blocks[110621])

    line_idx_addr_w = locate_line_idx_by_instr_addr(ass_lines, instr_addr_w)
    line_idx_addr_r = locate_line_idx_by_instr_addr(ass_lines, instr_addr_r)

    line_idx_mem_copy_calls = locate_mem_copy_call(ass_lines, line_idx_addr_w, line_idx_addr_r)

    buf_size = extract_strcpy_args(ass_lines, ass_v_blocks, line_idx_mem_copy_calls)

def read_memfile():
    """Try to read the memfile's content. According to the file (https://github.com/melynx/peekaboo/blob/37a10a64a06b55d349bbd1d874198c754cdbbde9/pypeekaboo/pypeekaboo.py#L154-L155),
    memfile contains the value and size of one address. We want to know the value or size of user input. 
    But it shows that the value and size are not accurate and we cannot know the size of one address at certain time (before running vulnerable()).
    Thus we cannot use this method to know the length of user input.
    """
    path = "../data/buffer_overflow-6555(vulnerable_trace)/6555/memfile"
    path = "../data/16315.memfile"
    with open(path, "rb") as f:
        memfile = f.read()
        # a = memfile.find(b'\x7f\xff\xa7\x5c\xa3\xe8') 7fffa75cb441
        data = memfile
        pat = b'\x44\xb4\x5c\xa7\xff\x7f\x00\x00' # 6555
        pat = b'\x32\xe4\xff\xff\xff\x7f\x00\x00' # 16189
        pat = b'\x2a\xe4\xff\xff\xff\x7f\x00\x00' # 16262
        pat = b'\x2e\xe4\xff\xff\xff\x7f\x00\x00' # 16315
        found = True
        while(found):
            a = data.find(pat)
            if a==-1:
                break
            print(a)
            print(data[a:a+24])
            print("--------------------")
            data = data[a+24:]


if __name__ == "__main__":

    trace_idx = "16684" # 6555 16609
    trace_s_path = f"./data/{trace_idx}.all"
    trace_v_path = f"./data/{trace_idx}.allrm"
    instr_addr_set_canary, instr_addr_chk_canary = "0x7f81b913f199", "0x7f81b913f1c0"
    instr_addr_set_canary, instr_addr_chk_canary = "0x7ffff3dd8161", "0x7ffff3dd8197"
    instr_addr_set_canary, instr_addr_chk_canary = "0x7ffff3dd817a", "0x7ffff3dd81ce"
    main(trace_s_path, trace_v_path, instr_addr_set_canary, instr_addr_chk_canary)
    # read_memfile()