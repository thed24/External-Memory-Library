namespace ExternalMemoryManipulator.Native
{
    public class MarshaledNativeMethods
    {
        private readonly int ProcessId;

        public MarshaledNativeMethods(string processName)
        {
            ProcessId = GetProcessIdByName(processName);
        }

        public IntPtr ReadMemory(IntPtr address)
        {
            return NativeMethods.read(ProcessId, address);
        }

        public void ReadBytesFromMemory(IntPtr address, byte[] buffer, int size)
        {
            NativeMethods.read_memory(ProcessId, address, buffer, size);
        }

        public void ReadBytesFromMemory(IntPtr address, IntPtr bufferPtr, int size)
        {
            NativeMethods.read_memory(ProcessId, address, bufferPtr, size);
        }

        public void WriteMemory(IntPtr address, byte[] buffer)
        {
            NativeMethods.write(ProcessId, address, buffer);
        }

        public IntPtr GetModuleBaseAddress(string moduleName, IntPtr offset)
        {
            return NativeMethods.get_module_base_address(ProcessId, moduleName, offset);
        }

        public int GetProcessIdByName(string processName)
        {
            return NativeMethods.get_process_by_name(processName);
        }

        public bool InitializeDriver()
        {
            return NativeMethods.initialize();
        }
    }
}