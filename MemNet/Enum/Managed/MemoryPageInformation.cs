namespace MemNet.Enum.Managed;

/// <summary>
/// Contains information about a memory page in the target process.
/// A managed representation of the MEMORY_BASIC_INFORMATION structure.
/// </summary>
public struct MemoryPageInformation
{
    public IntPtr BaseAddress;
    public IntPtr AllocationBase;
    public MemoryProtection AllocationProtect;
    public ulong RegionSize;
    public MemoryState State;
    public MemoryProtection Protect;
    public MemoryType Type;
}