using System.Runtime.InteropServices;
using System.Text;

namespace MemNet.Native;

// ReSharper disable InconsistentNaming
// ReSharper disable FieldCanBeMadeReadOnly.Global
// ReSharper disable MemberCanBePrivate.Global

/// <summary>
/// Contains basic information about a process.
/// Used with NtQueryInformationProcess(ProcessBasicInformation).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct PROCESS_BASIC_INFORMATION
{
    public IntPtr Reserved1;
    public IntPtr PebBaseAddress;
    public IntPtr Reserved2_0;
    public IntPtr Reserved2_1;
    public IntPtr UniqueProcessId;
    public IntPtr Reserved3;
}

/// <summary>
/// Process Environment Block.
/// Contains process-wide information including loader data.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct PEB
{
    public byte InheritedAddressSpace;
    public byte ReadImageFileExecOptions;
    public byte BeingDebugged;
    public byte BitField;
    public IntPtr Mutant;
    public IntPtr ImageBaseAddress;
    public IntPtr Ldr; // Pointer to PEB_LDR_DATA
    // Additional fields omitted - we only need Ldr
}

/// <summary>
/// Loader data structure containing module lists.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct PEB_LDR_DATA
{
    public uint Length;
    public byte Initialized;
    public IntPtr SsHandle;
    public LIST_ENTRY InLoadOrderModuleList;
    public LIST_ENTRY InMemoryOrderModuleList;
    public LIST_ENTRY InInitializationOrderModuleList;
}

/// <summary>
/// Doubly-linked list entry.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct LIST_ENTRY
{
    public IntPtr Flink;
    public IntPtr Blink;
}

/// <summary>
/// Loader data table entry - represents a loaded module.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct LDR_DATA_TABLE_ENTRY
{
    public LIST_ENTRY InLoadOrderLinks;
    public LIST_ENTRY InMemoryOrderLinks;
    public LIST_ENTRY InInitializationOrderLinks;
    public IntPtr DllBase;
    public IntPtr EntryPoint;
    public uint SizeOfImage;
    public UNICODE_STRING FullDllName;
    public UNICODE_STRING BaseDllName;
    // Additional fields omitted
}

/// <summary>
/// Unicode string structure used by the NT API.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct UNICODE_STRING
{
    public ushort Length;
    public ushort MaximumLength;
    public IntPtr Buffer;

    /// <summary>
    /// Reads the string content from a target process.
    /// </summary>
    public string ReadString(Func<IntPtr, int, byte[]> readMemory)
    {
        if (Buffer == IntPtr.Zero || Length == 0)
            return string.Empty;

        try
        {
            byte[] nameBytes = readMemory(Buffer, Length);
            return Encoding.Unicode.GetString(nameBytes);
        }
        catch
        {
            return string.Empty;
        }
    }
}

/// <summary>
/// Object attributes structure used in NT API calls.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct OBJECT_ATTRIBUTES
{
    public int Length;
    public IntPtr RootDirectory;
    public IntPtr ObjectName;
    public uint Attributes;
    public IntPtr SecurityDescriptor;
    public IntPtr SecurityQualityOfService;

    /// <summary>
    /// Initializes the structure with default values.
    /// </summary>
    public static OBJECT_ATTRIBUTES Create()
    {
        return new OBJECT_ATTRIBUTES
        {
            Length = Marshal.SizeOf<OBJECT_ATTRIBUTES>(),
            RootDirectory = IntPtr.Zero,
            ObjectName = IntPtr.Zero,
            Attributes = 0,
            SecurityDescriptor = IntPtr.Zero,
            SecurityQualityOfService = IntPtr.Zero
        };
    }
}

/// <summary>
/// Client ID structure containing process and thread identifiers.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct CLIENT_ID
{
    public IntPtr UniqueProcess;
    public IntPtr UniqueThread;
}

/// <summary>
/// Memory basic information structure.
/// Already defined in your codebase - included here for completeness.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct MEMORY_BASIC_INFORMATION
{
    public IntPtr BaseAddress;
    public IntPtr AllocationBase;
    public uint AllocationProtect;
    public IntPtr RegionSize;
    public uint State;
    public uint Protect;
    public uint Type;
}

[Flags]
public enum ProcessAccessRights : uint
{
    PROCESS_TERMINATE = 0x0001,
    PROCESS_CREATE_THREAD = 0x0002,
    PROCESS_SET_SESSIONID = 0x0004,
    PROCESS_VM_OPERATION = 0x0008,
    PROCESS_VM_READ = 0x0010,
    PROCESS_VM_WRITE = 0x0020,
    PROCESS_DUP_HANDLE = 0x0040,
    PROCESS_CREATE_PROCESS = 0x0080,
    PROCESS_SET_QUOTA = 0x0100,
    PROCESS_SET_INFORMATION = 0x0200,
    PROCESS_QUERY_INFORMATION = 0x0400,
    PROCESS_SUSPEND_RESUME = 0x0800,
    PROCESS_GET_CONTEXT = 0x1000,
    PROCESS_SET_CONTEXT = 0x2000,
    PROCESS_QUERY_LIMITED_INFORMATION = 0x2000, // Introduced in Windows Server 2003
    PROCESS_ALL_ACCESS = 0x000F0000 | 0x001FFFFF
}

[StructLayout(LayoutKind.Sequential)]
internal struct MODULEINFO
{
    public IntPtr lpBaseOfDll;
    public uint SizeOfImage;
    public IntPtr EntryPoint;
}



// ReSharper restore InconsistentNaming
// ReSharper restore FieldCanBeMadeReadOnly.Global
// ReSharper restore MemberCanBePrivate.Global