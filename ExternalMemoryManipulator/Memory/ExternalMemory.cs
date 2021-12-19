using Process.NET.Memory;
using Process.NET.Native.Types;
using System.Runtime.InteropServices;
using System.Text;

namespace ExternalMemoryManipulator.Memory
{
    public class ExternalMemory : ProcessMemory
    {
        private readonly NativeProcesses ProcessMethods;

        public ExternalMemory(SafeMemoryHandle handle = null) : base(handle)
        {
            ProcessMethods = new NativeProcesses(Environment.GetEnvironmentVariable("PROCESS_NAME"));
            var initSucceed = ProcessMethods.InitializeDriver();

            if (initSucceed is false) throw new Exception("Driver is not running properly.");
        }

        public override byte[] Read(IntPtr intPtr, int length)
        {
            var buffer = new byte[length];
            ProcessMethods.ReadBytesFromMemory(intPtr, buffer, buffer.Length);

            return buffer;
        }

        public override T Read<T>(IntPtr intPtr)
        {
            try
            {
                var size = Marshal.SizeOf(typeof(T));
                var buffer = new byte[size];

                ProcessMethods.ReadBytesFromMemory(intPtr, buffer, buffer.Length);

                var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                var data = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));

                handle.Free();

                var pointerToHex = BitConverter.ToString(buffer).Replace("-", "");

                return data;
            }
            catch (Exception)
            {
                return default;
            }
        }

        public override int Write(IntPtr intPtr, byte[] bytesToWrite)
        {
            try
            {
                ProcessMethods.WriteMemory(intPtr, bytesToWrite);
                return 1;
            }
            catch 
            {
                return 0;
            }
        }

        public override void Write<T>(IntPtr intPtr, T value)
        {
            byte[] buffer = null;

            dynamic test = value;

            try
            {
                buffer = BitConverter.GetBytes(test);
            }
            catch
            {
                buffer = test;
            }

            ProcessMethods.WriteMemory(intPtr, buffer);
        }

        public string ReadUnicodeString(IntPtr address, int bufferSize)
        {
            var buffer = new byte[bufferSize];
            ProcessMethods.ReadBytesFromMemory(address, buffer, buffer.Length);
            return Encoding.Unicode.GetString(buffer);
        }

        public IntPtr GetModuleBaseAddress(string dll, IntPtr offset = default)
        {
            var baseAddress = ProcessMethods.GetModuleBaseAddress(dll, offset);
            return baseAddress;
        }

        public IntPtr ReadPointerChain(IntPtr address, params int[] ptrChainOffsets)
        {
            var currentAddress = address;

            foreach (var offset in ptrChainOffsets)
            {
                currentAddress = Read<IntPtr>(IntPtr.Add(currentAddress, offset));

                if (currentAddress == IntPtr.Zero)
                    return IntPtr.Zero;
            }

            return currentAddress;
        }

        public T ReadGenericType<T>(IntPtr address, int bufferSize, bool isIntPtr = false, int index = 0)
        {
            var byteArray = new byte[bufferSize];
            ProcessMethods.ReadBytesFromMemory(address, byteArray, byteArray.Length);

            var propertyType = typeof(T);
            var typeCode = Type.GetTypeCode(propertyType);

            switch (typeCode)
            {
                case TypeCode.Object:
                    if (isIntPtr)
                    {
                        switch (byteArray.Length)
                        {
                            case 1:
                                return (T)(object)new IntPtr(BitConverter.ToInt32(new byte[] { byteArray[index], 0x0, 0x0, 0x0 }, index));
                            case 2:
                                return (T)(object)new IntPtr(BitConverter.ToInt32(new byte[] { byteArray[index], byteArray[index + 1], 0x0, 0x0 }, index));
                            case 4:
                                return (T)(object)new IntPtr(BitConverter.ToInt32(byteArray, index));
                            case 8:
                                return (T)(object)new IntPtr(BitConverter.ToInt64(byteArray, index));
                        }
                    }
                    break;
                case TypeCode.Boolean:
                    return (T)(object)BitConverter.ToBoolean(byteArray, index);
                case TypeCode.Byte:
                    return (T)(object)byteArray[index];
                case TypeCode.Char:
                    return (T)(object)Encoding.UTF8.GetChars(byteArray)[index];
                case TypeCode.Double:
                    return (T)(object)BitConverter.ToDouble(byteArray, index);
                case TypeCode.Int16:
                    return (T)(object)BitConverter.ToInt16(byteArray, index);
                case TypeCode.Int32:
                    return (T)(object)BitConverter.ToInt32(byteArray, index);
                case TypeCode.Int64:
                    return (T)(object)BitConverter.ToInt64(byteArray, index);
                case TypeCode.Single:
                    return (T)(object)BitConverter.ToSingle(byteArray, index);
                case TypeCode.String:
                    throw new InvalidCastException("This method doesn't support string conversion.");
                case TypeCode.UInt16:
                    return (T)(object)BitConverter.ToUInt16(byteArray, index);
                case TypeCode.UInt32:
                    return (T)(object)BitConverter.ToUInt32(byteArray, index);
                case TypeCode.UInt64:
                    return (T)(object)BitConverter.ToUInt64(byteArray, index);
            }

            using var unmanaged = new LocalUnmanagedMemory(bufferSize);
            unmanaged.Write(byteArray);
            return unmanaged.Read<T>();
        }

        private static string GetGenericType<T>(Dictionary<int, T> list)
        {
            var type = list.GetType().GetProperty("Item")?.PropertyType;
            var typeName = type.Name.ToLower();
            return typeName;
        }
    }
}