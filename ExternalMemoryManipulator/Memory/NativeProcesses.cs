using System.Runtime.InteropServices;

namespace ExternalMemoryManipulator.Memory
{
    public class NativeProcesses
    {
        private readonly int pID;

        public NativeProcesses(string processName)
        {
            pID = GetProcessIdByName(processName);
        }

        public IntPtr ReadMemory(IntPtr lpBaseAddress)
        {
            return NativeMethods.read(pID, lpBaseAddress);
        }

        public void ReadBytesFromMemory(IntPtr lpBaseAddress, byte[] buffer, int size)
        {
            NativeMethods.read_memory(pID, lpBaseAddress, buffer, size);
        }

        public void WriteMemory(IntPtr lpBaseAddress, byte[] buffer)
        {
            NativeMethods.write(pID, lpBaseAddress, buffer);
        }

        public IntPtr GetModuleBaseAddress(string modName, IntPtr offset)
        {
            return NativeMethods.GetModuleBaseAddress(pID, modName, offset);
        }

        public int GetProcessIdByName(string procName)
        {
            return NativeMethods.GrabProcessByName(procName);
        }

        public bool InitializeDriver()
        {
            return NativeMethods.initialize();
        }

        private static class NativeMethods
        {
            [DllImport("TarkyDriver.dll", CharSet = CharSet.None, ExactSpelling = false,
                CallingConvention = CallingConvention.Cdecl)]
            internal static extern IntPtr read(int hProcess, IntPtr lpBaseAddress);

            [DllImport("TarkyDriver.dll", CharSet = CharSet.None, ExactSpelling = false,
                CallingConvention = CallingConvention.Cdecl)]
            internal static extern IntPtr read_memory(int hProcess, IntPtr lpBaseAddress, byte[] buffer, int size);

            [DllImport("TarkyDriver.dll", CharSet = CharSet.None, ExactSpelling = false,
                CallingConvention = CallingConvention.Cdecl)]
            internal static extern void write(int hProcess, IntPtr lpBaseAddress, byte[] buffer);

            [DllImport("TarkyDriver.dll", CharSet = CharSet.None, ExactSpelling = false,
                CallingConvention = CallingConvention.Cdecl)]
            public static extern IntPtr GetModuleBaseAddress(int procHandle, string modName, IntPtr gomOffset);

            [DllImport("TarkyDriver.dll", CharSet = CharSet.None, ExactSpelling = false,
                CallingConvention = CallingConvention.Cdecl)]
            public static extern int GrabProcessByName(string procName);

            [DllImport("TarkyDriver.dll", CharSet = CharSet.None, ExactSpelling = false,
                CallingConvention = CallingConvention.Cdecl)]
            public static extern bool initialize();
        }
    }
}