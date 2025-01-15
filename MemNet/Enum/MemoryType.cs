namespace Memlib.Enum;
    
// ReSharper disable InconsistentNaming
// ReSharper disable UnusedMember.Local
// ReSharper disable UnusedType.Global

[Flags]
public enum MemoryType : uint
{
    MEM_UNKNOWN    = 0x0,
    MEM_PRIVATE = 0x20000,
    MEM_MAPPED  = 0x40000,
    MEM_IMAGE   = 0x1000000
}