namespace MemNet.Enum;

// ReSharper disable InconsistentNaming
// ReSharper disable UnusedMember.Local
// ReSharper disable UnusedType.Global

[Flags]
public enum MemoryState : uint
{
    MEM_COMMIT  = 0x1000,
    MEM_RESERVE = 0x2000,
    MEM_FREE    = 0x10000
}