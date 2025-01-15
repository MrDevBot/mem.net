namespace Memlib.Enum;

// ReSharper disable InconsistentNaming
// ReSharper disable UnusedMember.Local
// ReSharper disable UnusedType.Global

[Flags]
public enum AllocationType : uint
{
    /// <summary>
    /// Allocates memory at the specified address. The size parameter must be greater than zero.
    /// </summary>
    MEM_COMMIT = 0x00001000,

    /// <summary>
    /// Reserves a range of the process's virtual address space without any actual physical storage being allocated.
    /// </summary>
    MEM_RESERVE = 0x00002000,

    /// <summary>
    /// Indicates that the data in the memory range specified by lpAddress and dwSize is no longer of interest.
    /// </summary>
    MEM_DECOMMIT = 0x00004000,

    /// <summary>
    /// Indicates that the pages of the specified region should be protected for access by multiple processes.
    /// </summary>
    MEM_SHARED = 0x00001000, // Note: This value overlaps with MEM_COMMIT in some contexts, careful usage is needed.

    /// <summary>
    /// Allocates memory using large page support.
    /// </summary>
    MEM_LARGE_PAGES = 0x20000000,

    /// <summary>
    /// Allocates memory that is suitable for use as AWE (Address Windowing Extensions) region.
    /// </summary>
    MEM_PHYSICAL = 0x00400000,

    /// <summary>
    /// Allocates memory that is mapped into the view of all processes. When specifying this flag, you must also specify the MEM_RESERVE flag.
    /// </summary>
    MEM_IMAGE = 0x01000000,

    /// <summary>
    /// Places the allocation at the highest possible address.
    /// </summary>
    MEM_TOP_DOWN = 0x00100000
}