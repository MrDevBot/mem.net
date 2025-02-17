namespace MemNet.Enum.Managed;

/// <summary>
/// Contains information about a module loaded in the target process.
/// A managed representation of the MODULEINFO structure with additional data.
/// </summary>
public struct ModuleInfo
{
    public string ModuleName;
    public IntPtr Base;
    public IntPtr EntryPoint;
    public uint SizeOfImage;
}