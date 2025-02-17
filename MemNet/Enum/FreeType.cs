namespace MemNet.Enum;

// ReSharper disable InconsistentNaming
// ReSharper disable UnusedMember.Local
// ReSharper disable UnusedType.Global

[Flags]
public enum FreeType : uint
{
    /// <summary>
    /// Decommits the specified region of committed pages. After the operation, the pages are in the reserved state.
    /// </summary>
    MEM_DECOMMIT = 0x00004000,

    /// <summary>
    /// Releases the specified region of pages. After this operation, the pages are in the free state, and are available for subsequent allocation operations.
    /// </summary>
    MEM_RELEASE = 0x00008000
}