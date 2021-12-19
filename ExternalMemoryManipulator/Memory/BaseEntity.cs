using System.Runtime.InteropServices;

namespace ExternalMemoryManipulator.Memory
{
    [StructLayout(LayoutKind.Explicit)]
    internal struct BaseEntity
    {

    }
    public class DynamicFieldOffsetAttribute : Attribute
    {
        int hash;

        //Contained in this class, for the sake of this code's simplicity
        public static Dictionary<int, int> OffsetDict;

        //Analogous to FixedOffsetAttribute
        public int Value { get { return OffsetDict[hash]; } }

        public DynamicFieldOffsetAttribute(string name)
        {
            hash = name.GetHashCode();
        }
    }
}
