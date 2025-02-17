using System.Runtime.InteropServices;

namespace MemNet.Native;

// ReSharper disable InconsistentNaming
// ReSharper disable UnusedMember.Local
// ReSharper disable UnusedType.Global

/// <summary>
///
/// https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-moduleinfo
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct MODULEINFO
{
    public IntPtr lpBaseOfDll;
    public uint SizeOfImage;
    public IntPtr EntryPoint;
}