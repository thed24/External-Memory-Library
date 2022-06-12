using ExternalMemoryManipulator.Native;
using System.Runtime.InteropServices;
using System.Text;

namespace ExternalMemoryManipulator.Memory
{
    public class MemoryManipulator
    {
        private static readonly MarshaledNativeMethods ProcessMethods;

        static MemoryManipulator()
        {
            ProcessMethods = new MarshaledNativeMethods(Environment.GetEnvironmentVariable("PROCESS_NAME"));

            var initializeSucceed = ProcessMethods.InitializeDriver();

            if (initializeSucceed is false) throw new Exception("Driver is not running properly.");
        }

        /// <summary>
        /// Returns the base address of the specified module within the given process.
        /// </summary>
        public static IntPtr ReadBaseAddressFor(string dll, IntPtr offset = default)
        {
            var baseAddress = ProcessMethods.GetModuleBaseAddress(dll, offset);
            return baseAddress;
        }

        /// <summary>
        /// Returns a byte array containing the bytes retrieved from reading the given pointer.
        /// </summary>
        public static byte[] Read(IntPtr intPtr, int length)
        {
            var buffer = new byte[length];
            ProcessMethods.ReadBytesFromMemory(intPtr, buffer, buffer.Length);

            return buffer;
        }

        /// <summary>
        /// Reads the memory at the pointer into the given buffer pointer.
        /// </summary>
        public static void ReadIntoBuffer(IntPtr intPtr, IntPtr bufferPtr, int length)
        {
            ProcessMethods.ReadBytesFromMemory(intPtr, bufferPtr, length);
        }

        /// <summary>
        /// Returns an encoded string by reading the bytes from the given pointer.
        /// </summary>
        public static string Read(IntPtr address, Encoding encoding, int bufferSize)
        {
            var buffer = new byte[bufferSize];
            ProcessMethods.ReadBytesFromMemory(address, buffer, buffer.Length);
            return encoding.GetString(buffer);
        }

        /// <summary>
        /// Returns a new pointer by offsetting the given pointer as many times as needed.
        /// </summary>
        public static IntPtr Read(IntPtr address, params int[] offsets)
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

        /// <summary>
        /// Returns a generic type by reading the bytes at the given pointer.
        /// </summary>
        public static T Read<T>(IntPtr intPtr)
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
                Console.Write(e.Source);
                Console.Write(e.Message);
                return default;
            }
        }

        /// <summary>
        /// Writes the given bytes to the pointer.
        /// </summary>
        public static void Write(IntPtr intPtr, byte[] bytesToWrite)
        {
            try
            {
                ProcessMethods.WriteMemory(intPtr, bytesToWrite);
            }
            catch (Exception e)
            {
                Console.Write(e.Source);
                Console.Write(e.Message);
            }
        }

        /// <summary>
        /// Writes the bytes of the given value to the pointer.
        /// </summary>
        public static void Write<T>(IntPtr intPtr, T value)
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
                Console.Write(e.Source);
                Console.Write(e.Message);
            }

            ProcessMethods.WriteMemory(intPtr, buffer);
        }
    }
}