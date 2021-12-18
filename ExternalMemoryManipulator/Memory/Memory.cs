using System.Runtime.InteropServices;
using System.Text;

namespace ExternalMemoryManipulator.Memory
{
    public class Memory
    {
        private static NativeProcesses processMethods;

        static Memory()
        {
            processMethods = new NativeProcesses(Environment.GetEnvironmentVariable("PROCESS_NAME"));
            var initSucceed = processMethods.Init();

            if (initSucceed is false) throw new Exception("Driver is not running properly.");
        }

        public static ulong GetModuleBaseAddress()
        {
            var baseAddress = processMethods.GetModuleBaseAddress("UnityPlayer.dll");
            return baseAddress;
        }

        public static byte[] ReadBytes(ulong address, int bufferSize)
        {
            var buffer = new byte[bufferSize];
            processMethods.ReadBytesFromMemory(address, buffer, buffer.Length);

            return buffer;
        }

        public static T Read<T>(ulong address, int offset)
        {
            try
            {
                Marshal.SizeOf(typeof(T));
                var buffer = new byte[offset];
                processMethods.ReadBytesFromMemory(address, buffer, buffer.Length);
                var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                handle.AddrOfPinnedObject();
                var data = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
                handle.Free();
                return data;
            }
            catch (Exception)
            {
                return default;
            }
        }

        public static T ReadGenericType<T>(ulong address, int bufferSize)
        {
            var buffer = new byte[bufferSize];
            processMethods.ReadBytesFromMemory(address, buffer, buffer.Length);

            switch (GetGenericType(new Dictionary<int, T>()))
            {
                case "single":
                    return (T)Convert.ChangeType(BitConverter.ToSingle(buffer, 0), typeof(T));
                case "string":
                    return (T)Convert.ChangeType(Encoding.UTF8.GetString(buffer), typeof(T));
                case "int32":
                    return (T)Convert.ChangeType(BitConverter.ToInt32(buffer, 0), typeof(T));
                case "int64":
                    return (T)Convert.ChangeType(BitConverter.ToInt64(buffer, 0), typeof(T));
                case "byte":
                    return (T)Convert.ChangeType(buffer[0], typeof(T));
                case "byte[]":
                    return (T)Convert.ChangeType(buffer, typeof(T));
                default:
                    return (T)Convert.ChangeType("0", typeof(T));
            }
        }

        public static string ReadUnicodeString(ulong address, int bufferSize)
        {
            var buffer = new byte[bufferSize];
            processMethods.ReadBytesFromMemory(address, buffer, buffer.Length);
            return Encoding.Unicode.GetString(buffer);
        }

        public static T ReadGenericType<T>(ulong address, int bufferSize, bool addBase = false)
        {
            var buffer = new byte[bufferSize];

            if (addBase)
                processMethods.ReadBytesFromMemory(GetModuleBaseAddress() + address, buffer, buffer.Length);
            else
                processMethods.ReadBytesFromMemory(address, buffer, buffer.Length);
            switch (GetGenericType(new Dictionary<int, T>()))
            {
                case "single":
                    return (T)Convert.ChangeType(BitConverter.ToSingle(buffer, 0), typeof(T));
                case "string":
                    return (T)Convert.ChangeType(Encoding.UTF8.GetString(buffer), typeof(T));
                case "int32":
                    return (T)Convert.ChangeType(BitConverter.ToInt32(buffer, 0), typeof(T));
                case "int64":
                    return (T)Convert.ChangeType(BitConverter.ToInt64(buffer, 0), typeof(T));
                case "byte":
                    return (T)Convert.ChangeType(buffer[0], typeof(T));
                case "byte[]":
                    return (T)Convert.ChangeType(buffer, typeof(T));
                default:
                    return (T)Convert.ChangeType("0", typeof(T));
            }
        }

        public static T Read<T>(ulong address, bool addBase = false, int customSize = -1)
        {
            try
            {
                var size = customSize == -1 ? Marshal.SizeOf(typeof(T)) : customSize;
                var buffer = new byte[size];

                if (addBase)
                    processMethods.ReadBytesFromMemory(GetModuleBaseAddress() + address, buffer, buffer.Length);
                else
                    processMethods.ReadBytesFromMemory(address, buffer, buffer.Length);

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

        public static ulong ReadPtr(ulong address, bool addBase = false, int customSize = -1)
        {
            try
            {
                var size = customSize == -1 ? Marshal.SizeOf(typeof(ulong)) : customSize;
                var buffer = new byte[size];

                if (addBase)
                    processMethods.ReadBytesFromMemory(GetModuleBaseAddress() + address, buffer, buffer.Length);
                else
                    processMethods.ReadBytesFromMemory(address, buffer, buffer.Length);

                var pointerToHex = BitConverter.ToString(buffer).Replace("-", "");
                var hexToInt = Convert.ToUInt64(pointerToHex, 16);

                return hexToInt;
            }
            catch (Exception)
            {
                return default;
            }
        }

        public static void WriteBytes(ulong address, dynamic val)
        {
            byte[] buffer = null;

            try
            {
                buffer = BitConverter.GetBytes(val);
            }
            catch
            {
                buffer = val;
            }

            processMethods.WriteMemory(address, buffer);
        }

        public static string GetGenericType<T>(Dictionary<int, T> list)
        {
            var type = list.GetType().GetProperty("Item")?.PropertyType;
            var typeName = type.Name.ToLower();
            return typeName;
        }

        public static ulong ReadPointerChain(ulong address, params uint[] ptrChainOffsets)
        {
            var currentAddress = address;

            foreach (var offset in ptrChainOffsets)
            {
                currentAddress = Read<ulong>(currentAddress + offset);

                if (currentAddress == 0)
                    return 0;
            }

            return currentAddress;
        }
    }
}