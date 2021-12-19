using System.Runtime.InteropServices;

namespace ExternalMemoryManipulator.Memory
{
    public class NativeMethods
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