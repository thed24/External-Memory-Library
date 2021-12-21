using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ExternalMemoryManipulator.Memory
{
    internal interface IMemoryManipulator
    {
        public IntPtr ReadBaseAddressFor(string dll, IntPtr offset = default);
        public byte[] Read(IntPtr intPtr, int length);
        public string Read(IntPtr address, Encoding encoding, int bufferSize);
        public IntPtr Read(IntPtr address, params int[] offsets);
        public T Read<T>(IntPtr intPtr);
        public void Write(IntPtr intPtr, byte[] bytesToWrite);
        public void Write<T>(IntPtr intPtr, T value);
    }
}
