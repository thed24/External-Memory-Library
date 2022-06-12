using System.Runtime.InteropServices;

namespace ExternalMemoryManipulator.Native
{
    public class NativeMethods
    {
        [DllImport("ExternalMemoryModule.dll", CharSet = CharSet.None, ExactSpelling = false,
            CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr read(int hProcess, IntPtr lpBaseAddress);

        [DllImport("ExternalMemoryModule.dll", CharSet = CharSet.None, ExactSpelling = false,
            CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr read_memory(int hProcess, IntPtr lpBaseAddress, byte[] buffer, int size);

        [DllImport("ExternalMemoryModule.dll", CharSet = CharSet.None, ExactSpelling = false,
            CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr read_memory(int hProcess, IntPtr lpBaseAddress, IntPtr bufferPtr, int size);

        [DllImport("ExternalMemoryModule.dll", CharSet = CharSet.None, ExactSpelling = false,
            CallingConvention = CallingConvention.Cdecl)]
        internal static extern void write(int hProcess, IntPtr lpBaseAddress, byte[] buffer);

        [DllImport("ExternalMemoryModule.dll", CharSet = CharSet.None, ExactSpelling = false,
            CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr get_module_base_address(int procHandle, string modName, IntPtr gomOffset);

        [DllImport("ExternalMemoryModule.dll", CharSet = CharSet.None, ExactSpelling = false,
            CallingConvention = CallingConvention.Cdecl)]
        public static extern int get_process_by_name(string procName);

        [DllImport("ExternalMemoryModule.dll", CharSet = CharSet.None, ExactSpelling = false,
            CallingConvention = CallingConvention.Cdecl)]
        public static extern bool initialize();
    }
}