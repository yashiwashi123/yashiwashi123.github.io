Looping over loaded modules of in peb
```c
struct _LIST_ENTRY *__fastcall loop_and_hash_over_loaded_modules_in_peb(int a1)
{
  unsigned int v2; // [rsp+20h] [rbp-28h]
  struct _LIST_ENTRY *i; // [rsp+28h] [rbp-20h]
  __int64 v4; // [rsp+30h] [rbp-18h]

  for ( i = NtCurrentPeb()->Ldr->InLoadOrderModuleList.Flink; i[3].Flink; i = i->Flink )
  {
    v4 = sub_1AC9099CAB0(i[6].Flink, LOWORD(i[5].Blink));
    v2 = 2 * sub_1AC9099C864(v4);
    if ( (unsigned int)crc32(v4, v2) == a1 )
      return i[3].Flink;
  }
  return 0i64;
}
```

CRC32 hash algorithm gets used to obfuscate api function names 
```c
 v2[0] = NtAllocateVirtualMemory_0;
  v3 = &unk_1AC909A1B08;
  v4 = &qword_1AC909A1650;
  v5 = RtlGetVersion_0;
  v6 = &unk_1AC909A1B08;
  v7 = &qword_1AC909A1608;
  v8 = NtCreateThread_0;
  v9 = &unk_1AC909A1B08;
  v10 = &unk_1AC909A1610;
  v11 = NtQueryInformationProcess_0;
  v12 = &unk_1AC909A1B08;
  v13 = &unk_1AC909A1618;
  v14 = NtQueryInformationThread_0;
  v15 = &unk_1AC909A1B08;
  v16 = &unk_1AC909A16B0;
  v17 = 0x5AAA327;
  v18 = &unk_1AC909A1B08;
  v19 = &unk_1AC909A1620;
  v20 = 0xA4163EBC;
  v21 = &unk_1AC909A1B08;
  v22 = &unk_1AC909A1628;
  v23 = 0x9EEE4B80;
  v24 = &unk_1AC909A1B08;
  v25 = &unk_1AC909A1630;
  v26 = 0x183679F2;
  ```
  
  Once we go through all of the hashes and convert them to actual win api functions, we can start analyzing the malware

  Here we find an encrypted string that gets decrypted and passed to CreateMutexW

  ```c
   string_decryption(&encrypted_mutex, decrypted_mutex_string);
  v13 = decrypted_mutex_string;
  qword_18000E3D0 = CreateMutexW_1(0i64, 0i64, decrypted_mutex_string);
  ```

  The string decryption function looks like this: 

  ```c
  __int64 __fastcall string_decryption(unsigned int *a1, __int64 a2)
{
  char v3; // [rsp+20h] [rbp-18h]
  unsigned __int16 i; // [rsp+24h] [rbp-14h]
  unsigned __int16 v5; // [rsp+28h] [rbp-10h]
  unsigned int v6; // [rsp+2Ch] [rbp-Ch]
  __int64 v8; // [rsp+40h] [rbp+8h]

  increment_by_1(0i64);
  v6 = *a1;
  v5 = *((_WORD *)a1 + 2) ^ *a1;
  v8 = (__int64)a1 + 6;
  for ( i = 0; i < (int)v5; ++i )
  {
    v3 = *(_BYTE *)(v8 + i);
    v6 = increment_by_1(v6);
    *(_BYTE *)(a2 + i) += v3 + 10;
    *(_BYTE *)(a2 + i) = v6 ^ v3;
  }
  return a2;
}
  ```

### Latrodectus Stealer 
BackGround: The stealer is gathered by emulating an infected host. One of the commands that gets sent is an instruction to download an additional payload from a specified uri on the C2 host. The following is an analysis of the stealer

The stealer code shares functions with latrodectus, specifically the resolution of win API functions via their hash. 
```c
  v5 = NtAllocateVirtualMemory_0;
  v6[0] = (__int64)&assignment_func;
  v6[1] = (__int64)&qword_1800C58B0;
  v9 = &RtlGetVersion;
  v12 = &NtCreateThread;
  v15 = &NtQueryInformationProcess;
  v18 = &NtQueryINformationThread;
  v21 = &unk_1800C5880;
  v24 = &unk_1800C5888;
  v27 = &unk_1800C5890;
  v30 = &unk_1800C5898;
  v33 = &unk_1800C58A0;
  v36 = &unk_1800C58A8;
  v39 = &unk_1800C58B8;
  v42 = &unk_1800C58C0;
  v45 = &unk_1800C58C8;
  v48 = &unk_1800C58D0;
  v51 = &unk_1800C58D8;
  v54 = &unk_1800C58E0;
  v57 = &unk_1800C58E8;
  v60 = &unk_1800C58F0;
  v63 = &unk_1800C58F8;
  v7 = RtlGetVersion_0;
  v8 = &assignment_func;
  v10 = NtCreateThread_0;
  v11 = &assignment_func;
  v13 = NtQueryInformationProcess_0;
  ```

  Forunately, the strings in the stealer code are no encrypted. This almost makes up for the annoyances caused by the hashed api functions. 

  Following the function hashing and address storage, we see cleartext strings indicating various registry entries the stealer queries: 
  ```c
    qword_1800C61E0 = (__int64)"Google\\Chrome";
  qword_1800C61E8 = (__int64)"Google\\Chrome SxS";
  qword_1800C61F0 = (__int64)"Xpom";
  qword_1800C61F8 = (__int64)"Yandex\\YandexBrowser";
  qword_1800C6200 = (__int64)"Comodo\\Dragon";
  qword_1800C6208 = (__int64)"Amigo";
  qword_1800C6210 = (__int64)"Orbitum";
  qword_1800C6218 = (__int64)"Bromium";
  qword_1800C6220 = (__int64)"Chromium";
  qword_1800C6228 = (__int64)"Nichrome";
  qword_1800C6230 = (__int64)"RockMelt";
  qword_1800C6238 = (__int64)"360Browser\\Browser";
  qword_1800C6240 = (__int64)"Vivaldi";
  qword_1800C6248 = (__int64)"Go!";
  qword_1800C6250 = (__int64)"Sputnik\\Sputnik";
  qword_1800C6258 = (__int64)"Kometa";
  qword_1800C6260 = (__int64)"uCozMedia\\Uran";
  qword_1800C6268 = (__int64)"QIP Surf";
  qword_1800C6270 = (__int64)"Epic Privacy Browser";
  qword_1800C6278 = (__int64)"CocCoc\\Browser";
  qword_1800C6280 = (__int64)"CentBrowser";
  qword_1800C6288 = (__int64)"7Star\\7Star";
  qword_1800C6290 = (__int64)"Elements Browser";
  qword_1800C6298 = (__int64)"Suhba";
  qword_1800C62A0 = (__int64)"Safer Technologies\\Secure Browser";
  qword_1800C62A8 = (__int64)"Rafotech\\Mustang";
  qword_1800C62B0 = (__int64)"Superbird";
  qword_1800C62B8 = (__int64)"Chedot";
  qword_1800C62C0 = (__int64)"Torch";
  qword_1800C62C8 = 0i64;
  qword_1800C61B0 = (__int64)"\\User Data\\Default\\Login Data";
  qword_1800C61B8 = (__int64)"\\User Data\\Default\\Web Data";
  qword_1800C61C0 = (__int64)"\\User Data\\Default\\Network\\Cookies";
  qword_1800C61C8 = (__int64)"Microsoft\\Edge";
  qword_1800C61D0 = 0i64;
  qword_1800C6098 = (__int64)"\\User Data\\Default\\Login Data";
  qword_1800C60A0 = (__int64)"\\User Data\\Default\\Web Data";
  qword_1800C60A8 = (__int64)"\\User Data\\Default\\Network\\Cookies";
  qword_1800C60B0 = (__int64)L"1Email";
  qword_1800C60B8 = (__int64)L"1SMTP Email Address";
  qword_1800C60C0 = (__int64)L"1SMTP Server";
  qword_1800C60C8 = (__int64)L"1POP3 Server";
  qword_1800C60D0 = (__int64)L"1POP3 User Name";
  qword_1800C60D8 = (__int64)L"1SMTP User Name";
  qword_1800C60E0 = (__int64)L"1NNTP Email Address";
  qword_1800C60E8 = (__int64)L"1NNTP User Name";
  qword_1800C60F0 = (__int64)L"1NNTP Server";
  qword_1800C60F8 = (__int64)L"1IMAP Server";
  qword_1800C6100 = (__int64)L"1IMAP User Name";
  qword_1800C6108 = (__int64)L"1HTTP User";
  qword_1800C6110 = (__int64)L"1HTTP Server URL";
  qword_1800C6118 = (__int64)L"1POP3 User";
  qword_1800C6120 = (__int64)L"1IMAP User";
  qword_1800C6128 = (__int64)L"1HTTPMail User Name";
  qword_1800C6130 = (__int64)L"1HTTPMail Server";
  qword_1800C6138 = (__int64)L"1SMTP User";
  qword_1800C6140 = (__int64)L"2POP3 Port";
  qword_1800C6148 = (__int64)L"2SMTP Port";
  qword_1800C6150 = (__int64)L"2IMAP Port";
  qword_1800C6158 = (__int64)L"1POP3 Password2";
  qword_1800C6160 = (__int64)L"1IMAP Password2";
  qword_1800C6168 = (__int64)L"1NNTP Password2";
  qword_1800C6170 = (__int64)L"1HTTPMail Password2";
  qword_1800C6178 = (__int64)L"1SMTP Password2";
  qword_1800C6180 = (__int64)L"3POP3 Password";
  qword_1800C6188 = (__int64)L"3IMAP Password";
  qword_1800C6190 = (__int64)L"3NNTP Password";
  qword_1800C6198 = (__int64)L"3HTTPMail Password";
  qword_1800C61A0 = (__int64)L"3SMTP Password";
  ```
  