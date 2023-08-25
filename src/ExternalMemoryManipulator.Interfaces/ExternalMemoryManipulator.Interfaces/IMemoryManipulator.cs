using System.Text;

namespace ExternalMemoryManipulator.Interfaces;

public interface IMemoryManipulator
{
    public void Write<T>(IntPtr intPtr, T value);
    public void Write(IntPtr intPtr, byte[] bytesToWrite);
    public T Read<T>(IntPtr intPtr) where T : unmanaged;
    public IntPtr Read(IntPtr address, params int[] offsets);
    public string Read(IntPtr address, Encoding encoding, int bufferSize);
    public void ReadIntoBuffer(IntPtr intPtr, IntPtr bufferPtr, int size);
    public byte[] Read(IntPtr intPtr, int size);
    public IntPtr ReadBaseAddressFor(string dll, IntPtr offset = default);
}