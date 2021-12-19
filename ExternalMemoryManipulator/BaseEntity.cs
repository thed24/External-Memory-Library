using System.Runtime.InteropServices;

namespace ExternalMemoryManipulator.Memory
{
    [StructLayout(LayoutKind.Explicit)]
    internal struct BaseEntity
    {
        [FieldOffset(0x0)] public IntPtr BaseAddress;
    }
}
