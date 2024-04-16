**Background** : This is an analysis of an unpacked bumblebee. This is meant to be a little reversing tutorial, as well as a demonstration of some basic reverse engineering and research skills I learned. 
The unpacked sample was downloaded from malware bazaar. I found the hash through this [article](https://bin.re/blog/the-dga-of-bumblebee/)

Bumblebee has two exports. As it is a dll, it's exports important because they contain the main functions of the malware.
We are going to look at the export starting at ```start	0000000140057D2C	[main entry]```
This is the 'main' function of the malware.  

![image1](/resources/bumblebee/image1.png)

![image2](/resources/bumblebee/image2.png)

When we scroll into the main function a little, we start noticing some intersting things. 
Let's start with this string:
![image3](/resources/bumblebee/image3.png)

I know that bumblebee uses RC4 encryption from two sources. One, from reading about the malware from articles like [this](https://www.proofpoint.com/us/blog/threat-insight/bumblebee-is-still-transforming) and two, from Flare's capa explorer plugin which indicates it found a pattern matching RC4 encryption. 

![image4](/resources/bumblebee/image4.png)

Shortly after this interesting string, a function call is made that takes another intersting string as an arugment

![alt text](/resources/bumblebee/image5.png)

![alt text](/resources/bumblebee/image-1.png)
here we get the hex representation of the second interesting string

![alt text](/resources/bumblebee/image-2.png)

If we use the initial interesting string as a passphrase for a RC4 encryption algorithm to decrypt the strange jumbled up encrypted looking string, we get an interesting output

![alt text](/resources/bumblebee/image-3.png)

The output reads `lnk1` 
This indicates that this version of bumblebee is being distributed via lnk email attachments. Furthermore, it possibly indicates that the authors of bumblebee set their versioning to indicate the initial vector of infection. 

Shortly after, the malware generates hashes and passes them to the `CreateEventW` API call

![alt text](/resources/bumblebee/image7.png)

`CreateEventW` is used to ensure the malware isn't already running, hence the check shown in the screenshot against error code 183 or `ERROR_ALREADY_EXISTS`

Following this we see some strings indicating the malware is collecting information about the infected host. Specifically username and Domain name.
![alt text](/resources/bumblebee/image8.png)
![alt text](/resources/bumblebee/image9.png)

### C2 Command Handling

This section of code looks like it's related to the handling of commands sent by the C2. There are various command names, each one doing something different. The commands I have found are shi, dij, dex, sdl, ins, gdt and plg
Let's look at what shi does in dpeth, then summarize what the rest of the commands do.

#### shi

If Bumblebee recieves the shi command, a function is called that does various interesting things.

First, an API call to GetSpecialFolderPath with an interesting array of paths
![alt text](/resources/bumblebee/image10.png)

Then a function is called that generates a random executable name. This is likely to avoid basic file-name based detection
![alt text](/resources/bumblebee/image11.png)

We then enter a subroutine that gathers information about the infected host.
![alt text](/resources/bumblebee/image12.png)

Bumblebee then loops through it's own threads using `CreateToolhelp32Snapshot`, tries finding a specific one, then opens it

![alt text](/resources/bumblebee/image13.png)

Bumblebee loads Advapi32.dll and uses 

```  
  hObject = a1;
  v7 = 0ui64;
  LibraryA = LoadLibraryA("Advapi32.dll");
  OpenProcessToken = GetProcAddress(LibraryA, "OpenProcessToken");
  CurrentProcess = GetCurrentProcess();
  if ( !(OpenProcessToken)(CurrentProcess, 40i64, &hObject) )
    return 0i64;
  if ( !LookupPrivilegeValueW(0i64, L"SeDebugPrivilege", &Luid) )
  {
    CloseHandle(hObject);
    return 0i64;
  }
  *(&v7 + 4) = Luid;
  LODWORD(v7) = 1;
  HIDWORD(v7) = 2;
  AdjustTokenPrivileges = GetProcAddress(LibraryA, "AdjustTokenPrivileges");
  v6 = (AdjustTokenPrivileges)(hObject, 0i64, &v7, 16i64, 0i64, 0i64);
  CloseHandle(hObject);
  return v6;
```
After performing privilege escalation, bumblebee writes shellcode to memory. Specifically, bumblebee overwrites the Sleep function in Windows with shellcode: 

```
  v6[0] = 1220555080;                           // These variables are actually shellcode beind displayed as decimal
                                                // 
  v6[1] = 826858033;
  v6[2] = 65583561;
  v6[3] = 28966912;
  v6[4] = 1207959552;
  v7 = -72;
  *&v8[7] = -338624751;
  v9 = -33;
  ModuleHandleA = GetModuleHandleA("kernel32.dll");
  *v8 = GetProcAddress(ModuleHandleA, "SleepEx");// overwriting Sleep with shellcode
  v3 = ntdll_handle_look_for_specific_mem_section(hProcess);
  WriteProcessMemory = GetProcAddress(ModuleHandleA, "WriteProcessMemory");
  VirtualProtectEx(hProcess, v3, 0x21ui64, 0x40u, &flOldProtect);
  result = (WriteProcessMemory)(hProcess, v3, v6, 33i64, &v11);
  if ( result )
  {
    VirtualProtectEx(hProcess, v3, 0x21ui64, flOldProtect, &flOldProtect);
    return 1i64;
  }
  return result;

```
Following this, bumblebee injects itself into NtQueueApcThread by 



#### dex
the `dex` command appears to queue bumblebee to create a randomly named .exe file



#### sdl 
Looks as though it runs cmd.exe and runs mkdir and copy
Additionally it looks like it is at least initializing COM proxies 
Also has ability to open Powershell
Potentially able to remove files from the victim 

#### ins 
powershell remove dirs 

#### gdt

Not too sure what this one does

#### plg
Domain generation and connection handling 