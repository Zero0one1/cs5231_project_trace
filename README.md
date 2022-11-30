# Trace-based Fault Localisation
 NUS CS5231 (System Security) term project for AY2022/2023 Semester 1
 Use improvements of execution traces from libpeekaboo to analyse the buffer overflow vulnerability.

## Tasks

Our task can be divided into 4 parts:
1. Implement functionality to generate the CFG (e.g., jump and call instructions). Match to 1st item in the plan of this document.
2. Extract the address range of the binary from the proc_map file. 2nd item in the plan.
3. Differ two traces to find the address of the broken canary and then find the instruction that initially writes to the canary. 3rd-5nd item.
4. Find the memory-copy API between two addresses and its argument (what is the buffer size) and how many bytes are needed to overflow the canary. 6nd-7nd item. TBD: handle the case of more variables except for the buffer array; handle other APIs or overflow reasons except for the strcpy(); (optinal) show the memory space between the buffer and the canary.

Besides,
- Design the poster. 
- Write the report.
- Record a video about the poster.
