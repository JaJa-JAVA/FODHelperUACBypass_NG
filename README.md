# TL;DR FODHelperUACBypass_NG

> ***FODHelperUACBypass_NG*** is a proof-of-concept implementation of the FODHelper UAC bypass technique from 2009, rewritten in C# and ***enhanced*** with modern evasion techniques such as indirect syscalls. instead of creating the registry keys we deconstructed it by ***creating a temporary key, populating and then renaming it*** - using indirect syscalls to bypass EDR hooks, while still leveraging the original FODHelper UAC bypass method of hijacking the `ms-settings` protocol handler. This fully bypasses MDA and MDE on a fully updated and patched Windows 10/11 system as of march 2026, and is designed to be used in red team engagements and penetration tests to demonstrate the technique and its effectiveness against modern defenses.

## Usage

### Build

The code is written in C#  and based on previous research referenced in the Resources section. It implments the registry key creation, value setting, and deletion steps using indirect syscalls (see [INDIRECT-SYSCALLS.md](INDIRECT-SYSCALLS.md) for details). The rename step uses the Win32 `RegRenameKey` API via P/Invoke.

Being a .Net binary allows us to use it with ExecuteAssembly in-memory execution techniques (supported by most C2 Frameworks), and also makes it easy to modify the payload command without needing to recompile (just change the command line argument).

Clone the repository and build the project using MSBuild or Visual Studio:

```powershell
git clone https://github.com/ThreathuntingAcademy/FODHelperUACBypass_NG.git
```

build the project using MSBuild or Visual Studio ***2026***:

```powershell
# Using MSBuild,  open a Developer Command Prompt for Visual Studio 2026 and run:
cd c:\path\to\FODHelperUACBypass_NG
msbuild FODHelperUACBypass_NG\FODHelperUACBypass_NG.csproj /p:Configuration=Release /p:Platform=x64

# Or using Visual Studio 2026
# Open FODHelperUACBypass_NG.sln and build in Release/x64
```

### Run

When no arguments are provided, notepad.exe will be used as the default payload for demonstration purposes. You can specify any command you want as the payload, but make sure to use the full path to the executable.

```powershell
# Execute the UAC bypass
.\FODHelperUACBypass_NG\bin\x64\Release\FODHelperUACBypass_NG.exe c:\path\to\payload.exe 

# Run diagnostic tests
.\FODHelperUACBypass_NG\bin\x64\Release\FODHelperUACBypass_NG.exe -test
```

> ***NOTE:*** When using your own payload, make sure it is `signed` (or at least has a code signing certificate `cloned` - ***Carboncopy/SignatureKid*** can do this). Also, ***have it present on the target system before executing the UAC bypass***, as it is the payload that will be executed when the hijacked registry key is triggered by `fodhelper.exe`. In a real attack scenario, the attacker would need to find a way to get the payload onto the target system (e.g. via phishing, file drop, etc.) before executing the UAC bypass.

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

### Using FODHelperUACBypass_NG with inlineExecute-Assembly (Cobalt-Strike).

Since we wrote the code in C# and compiled it as a .Net assembly, we can use it with in-memory execution techniques such as `inlineExecute-Assembly` in Cobalt Strike. This allows us to execute the UAC bypass without writing anything to disk, making it even more stealthy and effective against modern defenses.

From an unprivileged beacon, you can execute the UAC bypass with the following command (make sure to change the path to the assembly and the payload command as needed):

```powershell
inlineExecute-Assembly --dotnetassembly /opt/cobaltstrike/payloads/FODHelperUACBypass_NG.exe --assemblyargs "notepad.exe
```

Github repo inlineExecute-Assembly: <https://github.com/anthemtotheego/InlineExecute-Assembly>

---

## Blog 

A blog post and detailed explanation of the technique can be found in the blog post: [FODHelper UAC Bypass NG](https://www.threathuntingacademy.com/blog)

## Youtube Demo

[FODHelperUACBypass_NG Demo](https://youtu.be/nCyWBg6tdaw)

In the demo we use actual `cobaltstrike` payloads and an evasive loader written in .net to demonstrate the technique in a real-world scenario. The payloads are generated with `cobaltstrike`, the loader fetches them and then executes them via the UAC bypass (resulting in a beacon in high integrity).

- The ***Evasive Loader*** is a simple .Net assembly that fetches the payload from a C2 server and executes it in-memory. It is designed to be used as the payload for the UAC bypass, allowing us to demonstrate the technique with real Cobalt Strike beacons. (this is not the purpose of this project, but it serves as a good demonstration of how the UAC bypass can be used in a real attack scenario)

- The evasive loader **needs to be present on the target system** before running the UAC bypass, as it is the payload that will be executed when the hijacked registry key is triggered by `fodhelper.exe`. In a real attack scenario, the attacker would need to find a way to get the evasive loader onto the target system (e.g. via phishing, file drop, etc.) before executing the UAC bypass.

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
