# RTImplant
Just another casual shellcode native loader


# Some Features


- APIHashing   - Obfuscate IAT using API hashing
- RandomMutex  - Generate mutex unique to each device
- VM Check     - Checks if its inside a virtual machine
- BlockDLL     - Blocks non MSFT signed dlls to load and do hooking etc
- SandboxCheck - Checks the joined domain name and DC name to confirm if its right environment

Process injection using Shellcode UUIDs into Self. Since I intend to use this with DLL Hijack or DLL SideLoading i did not write a remote process injection for now


Currently to execute/trigger shellcode we are using EnumDesktopsW which accepts a callback function. We have atleast 100+ functions to replace with in future


Credits:
http://ropgadget.com/posts/abusing_win_functions.html
https://nytrosecurity.com/2019/06/30/writing-shellcodes-for-windows-x64/
