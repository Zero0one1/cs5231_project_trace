import pandas as pd
import os, re

READ_TRACE = "/home/cs5231project/Desktop/Peekaboo/read_trace"
#TRACE_PATH = "/home/cs5231project/Desktop/Project/buffer_overflow_normal/2710"
TRACE_PATH = "/home/cs5231project/Desktop/Project/buffer_overflow_stacksmash/2866"

PPROLOGUE_FILTER = "./cfg_pattern1.txt"
EPILOGUE_FILTER = "./cfg_pattern2.txt"
CALL_FILTER = "./cfg_pattern3.txt"
JMP_FILTER = "./cfg_pattern4.txt"
PRO_RAW = "./prologueLines.txt"
EPI_RAW = "./epilogueLines.txt"
CALL_RAW = "./callLines.txt"
JMP_RAW = "./jmpLines.txt"
CFG_FILE = "./cfg.txt"

instrRegex=re.compile("^\[[0-9]{6}\]")
addrRegex=re.compile("0x[[a-f0-9]{12}")

myColumns = ["Instruction_Num","Address","Opcode", "ASM_instruction"]
cfg_DF = pd.DataFrame(columns=myColumns)
#We wantform CFG, ENDBR64 (Intel CET), Prologue, Epilogue, various jumps [72 to 77 ??], call [e8 ??]
opCodeList = ["\[f3 0f 1e fa\]", "\[55\]","\[48 89 e5\]", "\[48 83 ec", "\[c9\]", "\[c3\]","\[72","\[73","\[74","\[75","\[76","\[77", "\[e8"] 

def GenerateIntermediateFiles(read_trace, trace_path):
    os.chdir("../data")
    output_prologueTrace = read_trace + " -p " + PPROLOGUE_FILTER + " " + trace_path + " > " + PRO_RAW
    output_epilogueTrace = read_trace + " -p " + EPILOGUE_FILTER + " " + trace_path + " > " + EPI_RAW
    output_callTrace = read_trace + " -p " + EPILOGUE_FILTER + " " + trace_path + " > " + CALL_RAW
    output_jmpTrace = read_trace + " -p " + EPILOGUE_FILTER + " " + trace_path + " > " + JMP_RAW
    print(output_prologueTrace)
    os.system(output_prologueTrace)
    CFGparseFile(PRO_RAW)
    print(output_epilogueTrace)
    os.system(output_epilogueTrace)
    CFGparseFile(EPI_RAW)        
    print(output_callTrace)
    os.system(output_callTrace)
    CFGparseFile(CALL_RAW)        
    # 72 ?? jb (jmp if below); # 73 ?? jnb (jmp if not below); # 74 ?? je (jmp if equal); 
    # 75 ?? jne (jmp if not equal); # 76 ?? jbe (jmp if below or equal); # 77 ?? ja (jmp if above);
    count = 72
    while count < 78:
        f = open(JMP_FILTER,"w")
        f.write(str(count) + " ??")
        f.close()
        print(output_jmpTrace)
        os.system(output_jmpTrace)
        CFGparseFile(JMP_RAW)        
        count = count + 1
    os.remove(PRO_RAW) #start cleanup
    os.remove(EPI_RAW)
    os.remove(CALL_RAW)
    os.remove(JMP_RAW)
    os.remove(JMP_FILTER)
    os.chdir("../code")

def CFGparseFile(filname):
    global cfg_DF
    tmpfile = open(filname, 'r')
    Lines = tmpfile.readlines()
    for singleLine in Lines:
        instr_search = re.search(instrRegex, singleLine)
        if instr_search:
            #print(singleLine)
            currInstrNum = instr_search.group(0)
            
            addr_search = re.search(addrRegex, singleLine)
            if addr_search:            
                currAddr = addr_search.group(0)
            
            splitter = singleLine.split(":\t ")
            tmpStr = splitter[1].split(" \t")
            currOpcode = tmpStr[0]
            currOpcode = '[' + currOpcode.strip() + ']'
            
            currASM = tmpStr[1]
            currASM = currASM.strip()
            currASM = currASM.replace('\t',' ')           
            #print(currInstrNum, currAddr, currOpcode, currASM)   
            tmpDF = pd.DataFrame([[currInstrNum,currAddr,currOpcode,currASM]], columns=myColumns)
            cfg_DF = pd.concat([cfg_DF,tmpDF])
        
def CFGparseRelevantFilesAndProcess():
    global cfg_DF
    cfg_DF.sort_values(["Instruction_Num"]) 
    cfg_DF.drop_duplicates(keep='first',inplace=True) #there's some overlap with libpeekaboo searches by pattern file
    cfg_DF = cfg_DF[(cfg_DF['Opcode'].str.contains('|'.join(opCodeList)))]
    cfg_DF.to_csv(CFG_FILE, sep='\t', na_rep='', header=True, index=False, encoding=None, date_format=None, doublequote=True)
    
def MainGenCFG(read_trace, trace_path):
    GenerateIntermediateFiles(read_trace, trace_path)
    CFGparseRelevantFilesAndProcess()
    
if __name__ == "__main__":
    MainGenCFG(READ_TRACE, TRACE_PATH)
    print("Done.")
