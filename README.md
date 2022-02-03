# RTImplant
RTImplant is just another Proof of Concept (PoC) Implant written in C and (x64)ASM. 
The Implant is intended for RedTeam and Adversary Simulation Operations, it does multiple environmental checks before it actually triggers shellcode execution.  

# RTImplant notable Features

- Debugger check - Very basic debugger check 
- APIHashing   - Obfuscate IAT using API hashing
- RandomMutex  - Generate mutex unique to each device
- VM Check     - Checks if its inside a virtual machine using display device names
- BlockDLL     - Blocks non MSFT signed dlls to load and do hooking etc
- SandboxCheck - Checks the joined domain name and DC name to confirm if its right environment
- TimeDelay    - Random Sleeping logic for sandbox evasions


After experimenting with my previous project - https://github.com/pwn1sher/uuid-loader I decided to stick with UUID as shellcode option for all my self injection payloads, because I feel large size shellcode like Cobalt Strike stageless are better off when represented as UUID Strings rather then encrypted hex array to prevent AV Heuristic or shellcode entropy detections

Currently to execute/trigger shellcode we are using EnumDesktopsW which accepts a callback function. We have atleast 100+ function alternatives to replace with in future

Note: I intend to use this loader as a DLL in combination with DLL SideLoading etc. Hence for now only self process injection is supported. 


# Credits:

http://ropgadget.com/posts/abusing_win_functions.html

https://nytrosecurity.com/2019/06/30/writing-shellcodes-for-windows-x64/
