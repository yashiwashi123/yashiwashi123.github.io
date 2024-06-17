
#### Debugging

Make sure you take a snapshot beforehand
Make sure your network is turned off

Always set a breackpoint at VirtualAlloc and VirtualProtect 
    `bp VirtualAlloc` and `bp VirtualProtect` in x64dbg console
These are specifically for memory allocation and changing the perms of a given memory allocation

Other useful generic breakpoints
Sleep
IsDebuggerPresent
CreateThread
CreateThreadEx
CreateProcessA
CreateProcessW
WriteProcessMemory

ResumeThread SetThreadContext Beep ReadProcessMemory