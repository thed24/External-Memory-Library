namespace ExternalMemoryManipulator.Memory
{
    public class MarshallNativeMethods
    {
        private readonly int processId;

        public MarshallNativeMethods(string processName)
        {
            processId = GetProcessIdByName(processName);
        }

        public IntPtr ReadMemory(IntPtr address)
        {
            return NativeMethods.read(processId, address);
        }

        public void ReadBytesFromMemory(IntPtr address, byte[] buffer, int size)
        {
            NativeMethods.read_memory(processId, address, buffer, size);
        }

        public void WriteMemory(IntPtr address, byte[] buffer)
        {
            NativeMethods.write(processId, address, buffer);
        }

        public IntPtr GetModuleBaseAddress(string moduleName, IntPtr offset)
        {
            return NativeMethods.GetModuleBaseAddress(processId, moduleName, offset);
        }

        public int GetProcessIdByName(string processName)
        {
            return NativeMethods.GrabProcessByName(processName);
        }

        public bool InitializeDriver()
        {
            return NativeMethods.initialize();
        }
    }
}