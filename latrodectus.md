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