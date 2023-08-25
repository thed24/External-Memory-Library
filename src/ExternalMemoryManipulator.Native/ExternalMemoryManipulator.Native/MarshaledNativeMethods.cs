namespace ExternalMemoryManipulator.Native;

public class MarshaledNativeMethods
{
    private readonly int _processId;

    public MarshaledNativeMethods(string processName)
    {
        _processId = GetProcessIdByName(processName);
    }

    public IntPtr ReadMemory(IntPtr address)
    {
        return NativeMethods.read(_processId, address);
    }

    public void ReadBytesFromMemory(IntPtr address, byte[] buffer, int size)
    {
        NativeMethods.read_memory(_processId, address, buffer, size);
    }

    public void ReadBytesFromMemory(IntPtr address, IntPtr bufferPtr, int size)
    {
        NativeMethods.read_memory(_processId, address, bufferPtr, size);
    }

    public void WriteMemory(IntPtr address, byte[] buffer)
    {
        NativeMethods.write(_processId, address, buffer);
    }

    public IntPtr GetModuleBaseAddress(string moduleName, IntPtr offset)
    {
        return NativeMethods.get_module_base_address(_processId, moduleName, offset);
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