using System.Runtime.InteropServices;

namespace MemNet.Native;

// ReSharper disable InconsistentNaming
// ReSharper disable UnusedMember.Local
// ReSharper disable UnusedType.Global

[StructLayout(LayoutKind.Sequential)]
public struct MEMORY_BASIC_INFORMATION
{
    public IntPtr BaseAddress;
    public IntPtr AllocationBase;
    public uint AllocationProtect;
    public IntPtr RegionSize;
    public uint State;
    public uint Protect;
    public uint Type;
}