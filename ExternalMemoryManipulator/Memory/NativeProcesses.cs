using System.Runtime.InteropServices;

namespace ExternalMemoryManipulator.Memory
{
    public class NativeProcesses
    {
        private readonly int pID;
        private readonly ulong gomOffset = 0x17F1CE8;
        public NativeProcesses(string processName)
        {
            pID = GetProcessIDByName(processName);
        }

        public ulong ReadMemory(ulong lpBaseAddress)
        {
            return NativeMethods.read(pID, lpBaseAddress);
        }

        public void ReadBytesFromMemory(ulong lpBaseAddress, byte[] buffer, int size)
        {
            NativeMethods.read_memory(pID, lpBaseAddress, buffer, size);
        }

        public void WriteMemory(ulong lpBaseAddress, byte[] buffer)
        {
            NativeMethods.write(pID, lpBaseAddress, buffer);
        }

        public ulong GetModuleBaseAddress(string modName)
        {
            return NativeMethods.GetModuleBaseAddress(pID, modName, gomOffset);
        }

        public int GetProcessIDByName(string procName)
        {
            return NativeMethods.GrabProcessByName(procName);
        }

        public bool Init()
        {
            return NativeMethods.initialize();
        }

        private static class NativeMethods
        {
            [DllImport("TarkyDriver.dll", CharSet = CharSet.None, ExactSpelling = false,
                CallingConvention = CallingConvention.Cdecl)]
            internal static extern ulong read(int hProcess, ulong lpBaseAddress);

            [DllImport("TarkyDriver.dll", CharSet = CharSet.None, ExactSpelling = false,
                CallingConvention = CallingConvention.Cdecl)]
            internal static extern ulong read_memory(int hProcess, ulong lpBaseAddress, byte[] buffer, int size);

            [DllImport("TarkyDriver.dll", CharSet = CharSet.None, ExactSpelling = false,
                CallingConvention = CallingConvention.Cdecl)]
            internal static extern void write(int hProcess, ulong lpBaseAddress, byte[] buffer);

            [DllImport("TarkyDriver.dll", CharSet = CharSet.None, ExactSpelling = false,
                CallingConvention = CallingConvention.Cdecl)]
            public static extern ulong GetModuleBaseAddress(int procHandle, string modName, ulong gomOffset);

            [DllImport("TarkyDriver.dll", CharSet = CharSet.None, ExactSpelling = false,
                CallingConvention = CallingConvention.Cdecl)]
            public static extern int GrabProcessByName(string procName);

            [DllImport("TarkyDriver.dll", CharSet = CharSet.None, ExactSpelling = false,
                CallingConvention = CallingConvention.Cdecl)]
            public static extern bool initialize();
        }
    }
}