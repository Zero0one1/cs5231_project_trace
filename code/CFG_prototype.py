import pandas as pd
import os, re

READ_TRACE = "/home/cs5231project/Desktop/Peekaboo/read_trace"
PPROLOGUE_FILTER = "/home/cs5231project/Desktop/cfg_pattern1.txt"
EPILOGUE_FILTER = "/home/cs5231project/Desktop/cfg_pattern2.txt"
TRACE_PATH = "/home/cs5231project/Desktop/Project/buffer_overflow_normal/2710"
#TRACE_PATH = "/home/cs5231project/Desktop/Project/buffer_overflow_stacksmash/2866"
PRO_RAW = "/home/cs5231project/Desktop/prologueLines.txt"
EPI_RAW = "/home/cs5231project/Desktop/epilogueLines.txt"
CFG_FILE = "/home/cs5231project/Desktop/cfg.txt"

instrRegex=re.compile("^\[[0-9]{6}\]")
addrRegex=re.compile("0x[[a-f0-9]{12}")

myColumns = ["Instruction_Num","Address","Opcode", "ASM_instruction"]
cfg_DF = pd.DataFrame(columns=myColumns)
#We want ENDBR64 (Intel CET), Prologue, Epilogue to form CFG
opCodeList = ["\[f3 0f 1e fa\]", "\[55\]","\[48 89 e5\]", "\[48 83 ec", "\[c9\]", "\[c3\]"] 
asmList = ["call 0x", "jmp"]

def GenerateIntermediateFiles():
    output_prologueTrace = READ_TRACE + " -p " + PPROLOGUE_FILTER + " " + TRACE_PATH + " > " + PRO_RAW
    output_epilogueTrace = READ_TRACE + " -p " + EPILOGUE_FILTER + " " + TRACE_PATH + " > " + EPI_RAW
    print(output_prologueTrace)
    os.system(output_prologueTrace)
    print(output_epilogueTrace)
    os.system(output_epilogueTrace)

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
            print(currInstrNum, currAddr, currOpcode, currASM)   
            tmpDF = pd.DataFrame([[currInstrNum,currAddr,currOpcode,currASM]], columns=myColumns)
            cfg_DF = pd.concat([cfg_DF,tmpDF])
        
def CFGparseRelevantFilesAndProcess():
    global cfg_DF
    CFGparseFile(PRO_RAW)
    CFGparseFile(EPI_RAW)        
    cfg_DF.sort_values(["Instruction_Num"]) 
    cfg_DF.drop_duplicates(keep='first',inplace=True) #there's some overlap with libpeekaboo searches by pattern file
    cfg_DF = cfg_DF[(cfg_DF['Opcode'].str.contains('|'.join(opCodeList))) | (cfg_DF['ASM_instruction'].str.contains('|'.join(asmList)))]
    cfg_DF.to_csv(CFG_FILE, sep='\t', na_rep='', header=True, index=False, encoding=None, date_format=None, doublequote=True)
    
def main():
    GenerateIntermediateFiles()
    CFGparseRelevantFilesAndProcess()
    
if __name__ == "__main__":
    main()
    print("Done.")
