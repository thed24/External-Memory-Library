using ExternalMemoryManipulator.Native;
using System.Runtime.InteropServices;
using System.Text;

namespace ExternalMemoryManipulator.Memory
{
    public class MemoryManipulator : IMemoryManipulator
    {
        private readonly MarshaledNativeMethods ProcessMethods;

        public MemoryManipulator(string processName = null)
        {
            ProcessMethods = new MarshaledNativeMethods(processName ?? Environment.GetEnvironmentVariable("PROCESS_NAME"));

            var initializeSucceed = ProcessMethods.InitializeDriver();

            if (initializeSucceed is false) 
                throw new Exception("Driver is not running properly.");
        }

        public IntPtr ReadBaseAddressFor(string dll, IntPtr offset = default)
        {
            var baseAddress = ProcessMethods.GetModuleBaseAddress(dll, offset);
            return baseAddress;
        }

        public byte[] Read(IntPtr intPtr, int length)
        {
            var buffer = new byte[length];
            ProcessMethods.ReadBytesFromMemory(intPtr, buffer, buffer.Length);

            return buffer;
        }

        public string Read(IntPtr address, Encoding encoding, int bufferSize)
        {
            var buffer = new byte[bufferSize];
            ProcessMethods.ReadBytesFromMemory(address, buffer, buffer.Length);
            return encoding.GetString(buffer);
        }

        public IntPtr Read(IntPtr address, params int[] offsets)
        {
            var currentAddress = address;

            foreach (var offset in offsets)
            {
                currentAddress = Read<IntPtr>(IntPtr.Add(currentAddress, offset));

                if (currentAddress == IntPtr.Zero)
                    return IntPtr.Zero;
            }

            return currentAddress;
        }

        public T Read<T>(IntPtr intPtr)
        {
            try
            {
                var size = typeof(T).IsEnum 
                    ? Marshal.SizeOf(Enum.GetUnderlyingType(typeof(T)))
                    : Marshal.SizeOf(typeof(T));

                var buffer = new byte[size];

                ProcessMethods.ReadBytesFromMemory(intPtr, buffer, buffer.Length);

                var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                var data = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
                handle.Free();

                return data;
            }
            catch (Exception e)
            {
                Console.Write(e);
                return default;
            }
        }

        public void Write(IntPtr intPtr, byte[] bytesToWrite)
        {
            try
            {
                ProcessMethods.WriteMemory(intPtr, bytesToWrite);
            }
            catch (Exception e)
            {
                Console.Write(e);
            }
        }

        public void Write<T>(IntPtr intPtr, T value)
        {
            var size = Marshal.SizeOf(typeof(T));
            var buffer = new byte[size];
            var ptr = Marshal.AllocHGlobal(size);

            try
            {
                Marshal.StructureToPtr(value, ptr, false);
                Marshal.Copy(ptr, buffer, 0 ,size);
                Marshal.FreeHGlobal(ptr);
            }
            catch (Exception e)
            {
                Console.Write(e);
            }

            ProcessMethods.WriteMemory(intPtr, buffer);
        }
    }
}