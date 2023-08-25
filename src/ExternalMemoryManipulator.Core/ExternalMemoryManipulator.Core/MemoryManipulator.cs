using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using ExternalMemoryManipulator.Interfaces;
using ExternalMemoryManipulator.Native;

namespace ExternalMemoryManipulator.Core;

public class MemoryManipulator : IMemoryManipulator
{
    private readonly MarshaledNativeMethods _processMethods;

    public MemoryManipulator()
    {
        string? process = Environment.GetEnvironmentVariable("PROCESS_NAME");
        if (process is null)
        {
            throw new Exception("PROCESS_NAME environment variable is not set.");
        }

        _processMethods = new MarshaledNativeMethods(process);

        bool initializeSucceed = _processMethods.InitializeDriver();
        if (initializeSucceed is false)
        {
            throw new Exception("Driver is not running properly.");
        }
    }

    /// <summary>
    ///     Returns the base address of the specified module within the given process.
    /// </summary>
    public IntPtr ReadBaseAddressFor(string dll, IntPtr offset = default)
    {
        try
        {
            return _processMethods.GetModuleBaseAddress(dll, offset);
        }
        catch
        { 
            return IntPtr.Zero; 
        }
    }

    /// <summary>
    ///     Returns a byte array containing the bytes retrieved from reading the given pointer.
    /// </summary>
    public byte[] Read(IntPtr intPtr, int length)
    {
        try
        {
            byte[] buffer = new byte[length];

            _processMethods.ReadBytesFromMemory(intPtr, buffer, buffer.Length);

            return buffer;
        }
        catch
        {
            return Array.Empty<byte>();
        }
    }

    /// <summary>
    ///     Reads the memory at the pointer into the given buffer pointer.
    /// </summary>
    public void ReadIntoBuffer(IntPtr intPtr, IntPtr bufferPtr, int length)
    {
        _processMethods.ReadBytesFromMemory(intPtr, bufferPtr, length);
    }

    /// <summary>
    ///     Returns an encoded string by reading the bytes from the given pointer.
    /// </summary>
    public string Read(IntPtr address, Encoding encoding, int bufferSize)
    {
        try
        {
            byte[] buffer = new byte[bufferSize];
            _processMethods.ReadBytesFromMemory(address, buffer, buffer.Length);
            return encoding.GetString(buffer);
        }
        catch
        {
            return string.Empty;
        }
    }

    /// <summary>
    ///     Returns a new pointer by offsetting the given pointer as many times as needed.
    /// </summary>
    public IntPtr Read(IntPtr address, params int[] offsets)
    {
        try
        {
            IntPtr currentAddress = address;

            foreach (int offset in offsets)
            {
                currentAddress = Read<IntPtr>(IntPtr.Add(currentAddress, offset));

                if (currentAddress == IntPtr.Zero)
                {
                    return IntPtr.Zero;
                }
            }

            return currentAddress;
        }
        catch
        {
            return IntPtr.Zero;
        }
    }

    /// <summary>
    ///     Returns a generic type by reading the bytes at the given pointer.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public T Read<T>(IntPtr intPtr) where T : unmanaged
    {
        try
        {
            unsafe
            {
                int size = Unsafe.SizeOf<T>();
                Span<byte> buffer = stackalloc byte[size];
                IntPtr bufferPtr = (IntPtr)Unsafe.AsPointer(ref MemoryMarshal.GetReference(buffer));
                _processMethods.ReadBytesFromMemory(intPtr, bufferPtr, size);
                return MemoryMarshal.Read<T>(buffer);
            }
        }
        catch
        {
            return default;
        }
    }

    /// <summary>
    ///     Writes the given bytes to the pointer.
    /// </summary>
    public void Write(IntPtr intPtr, byte[] bytesToWrite)
    {
        try
        {
            _processMethods.WriteMemory(intPtr, bytesToWrite);
        }
        catch (Exception e)
        {
            Console.Write(e.Source);
            Console.Write(e.Message);
        }
    }

    /// <summary>
    ///     Writes the bytes of the given value to the pointer.
    /// </summary>
    public void Write<T>(IntPtr intPtr, T value)
    {
        int size = Marshal.SizeOf(typeof(T));
        byte[] buffer = new byte[size];
        IntPtr ptr = Marshal.AllocHGlobal(size);

        try
        {
            Marshal.StructureToPtr(value, ptr, false);
            Marshal.Copy(ptr, buffer, 0, size);
            Marshal.FreeHGlobal(ptr);
        }
        catch (Exception e)
        {
            Console.Write(e.Source);
            Console.Write(e.Message);
        }

        _processMethods.WriteMemory(intPtr, buffer);
    }
}