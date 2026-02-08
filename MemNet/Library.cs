using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using MemNet.Enum;
using MemNet.Enum.Managed;
using MemNet.Native;
using Serilog;

namespace MemNet;

/// <summary>
/// Provides methods to open a process, read and write memory, allocate and deallocate memory,
/// perform pattern searches, and manage modules and memory pages.
/// </summary>
public sealed class Memory : IDisposable
{
    /// <summary>
    /// Handle to the target process.
    /// </summary>
    private IntPtr _processHandle = IntPtr.Zero;

    /// <summary>
    /// The ID of the target process.
    /// </summary>
    private readonly int _processId;

    /// <summary>
    /// A logger instance used for debug and diagnostic messages.
    /// </summary>
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="Memory"/> class.
    /// </summary>
    /// <param name="processId">Process ID of the target process.</param>
    /// <param name="logger">Optional logger instance (defaults to Serilog.Log.Logger).</param>
    public Memory(int processId, ILogger? logger = null)
    {
        _logger = logger ?? Log.Logger;
        _processId = processId;
    }

    /// <summary>
    /// Opens the target process with the specified access rights.
    /// </summary>
    /// <param name="processAccessRights">The desired access rights.</param>
    /// <exception cref="Win32Exception">Thrown if the process cannot be opened.</exception>
    public void Open(
        ProcessAccessRights processAccessRights = ProcessAccessRights.PROCESS_VM_READ |
                                                  ProcessAccessRights.PROCESS_VM_WRITE |
                                                  ProcessAccessRights.PROCESS_QUERY_INFORMATION |
                                                  ProcessAccessRights.PROCESS_VM_OPERATION)
    {
        if (_processHandle != IntPtr.Zero)
            Close();

        _processHandle = OpenProcess((uint)processAccessRights, false, _processId);
        _logger.Debug("Opened {ProcessId} with {AccessRights}.", _processId, processAccessRights);

        if (_processHandle == IntPtr.Zero)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                $"Failed to open process with ID {_processId}."
            );
        }
    }

    /// <summary>
    /// Hijacks an existing handle for the target process.
    /// </summary>
    /// <param name="existingHandle">An existing valid handle to the target process.</param>
    /// <exception cref="InvalidOperationException">Thrown if the process is already open.</exception>
    /// <exception cref="ArgumentException">Thrown if the provided handle is zero/invalid.</exception>
    public void Open(IntPtr existingHandle)
    {
        if (existingHandle == IntPtr.Zero)
            throw new ArgumentException("Handle cannot be zero.", nameof(existingHandle));

        if (_processHandle != IntPtr.Zero)
        {
            throw new InvalidOperationException("Process already open. Close before hijacking another handle.");
        }

        _processHandle = existingHandle;
        _logger.Debug("Hijacked handle for process {ProcessId}.", _processId);
    }

    /// <summary>
    /// Retrieves a list of modules loaded by the target process.
    /// </summary>
    /// <returns>A list of <see cref="ModuleInfo"/> objects.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the process is not open.</exception>
    /// <exception cref="Win32Exception">Thrown if enumeration of modules fails.</exception>
    public List<ModuleInfo> Modules()
    {
        if (_processHandle == IntPtr.Zero)
            throw new InvalidOperationException($"Process with ID {_processId} is not open.");

        var modules = new List<ModuleInfo>();
        IntPtr[] moduleHandles = new IntPtr[1024];
        uint cb = (uint)(IntPtr.Size * moduleHandles.Length);

        if (!EnumProcessModulesEx(_processHandle, moduleHandles, cb, out var lpcbNeeded, 0x03))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                $"Failed to enumerate process modules for process {_processId}."
            );
        }

        if (lpcbNeeded > cb)
        {
            moduleHandles = new IntPtr[lpcbNeeded / (uint)IntPtr.Size];
            cb = lpcbNeeded;

            if (!EnumProcessModulesEx(_processHandle, moduleHandles, cb, out lpcbNeeded, 0x03))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    $"Failed to enumerate process modules for process {_processId}."
                );
            }
        }

        int numModules = (int)(lpcbNeeded / (uint)IntPtr.Size);
        for (int i = 0; i < numModules; i++)
        {
            StringBuilder moduleName = new StringBuilder(256);
            if (GetModuleBaseName(_processHandle, moduleHandles[i], moduleName, (uint)moduleName.Capacity) == 0)
                continue;

            if (GetModuleInformation(_processHandle, moduleHandles[i], out MODULEINFO moduleInfo,
                    (uint)Marshal.SizeOf<MODULEINFO>()))
            {
                modules.Add(new ModuleInfo
                {
                    ModuleName = moduleName.ToString(),
                    Base = moduleInfo.lpBaseOfDll,
                    SizeOfImage = moduleInfo.SizeOfImage,
                    EntryPoint = moduleInfo.EntryPoint
                });
            }
        }

        return modules;
    }

    /// <summary>
    /// Enumerates memory pages in the target process.
    /// </summary>
    /// <returns>An <see cref="IEnumerable{T}"/> of <see cref="MemoryPageInformation"/> describing the process pages.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the process is not open.</exception>
    public IEnumerable<MemoryPageInformation> Query()
    {
        if (_processHandle == IntPtr.Zero)
            throw new InvalidOperationException($"Process with ID {_processId} is not open.");

        var address = IntPtr.Zero;
        var sizeOfMbi = Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();

        while (true)
        {
            IntPtr pMbi = Marshal.AllocHGlobal(sizeOfMbi);
            try
            {
                int status = NtQueryVirtualMemory(
                    _processHandle,
                    address,
                    0, // MemoryBasicInformation
                    pMbi,
                    sizeOfMbi,
                    out var returnedBytes
                );

                if (!NT_SUCCESS(status) || returnedBytes.ToInt64() == 0)
                    break;

                MEMORY_BASIC_INFORMATION mbi = Marshal.PtrToStructure<MEMORY_BASIC_INFORMATION>(pMbi);
                yield return new MemoryPageInformation
                {
                    BaseAddress = mbi.BaseAddress,
                    AllocationBase = mbi.AllocationBase,
                    AllocationProtect = (MemoryProtection)mbi.AllocationProtect,
                    RegionSize = (ulong)mbi.RegionSize.ToInt64(),
                    State = (MemoryState)mbi.State,
                    Protect = (MemoryProtection)mbi.Protect,
                    Type = (MemoryType)mbi.Type
                };

                long nextAddress = mbi.BaseAddress.ToInt64() + mbi.RegionSize;
                if (nextAddress < 0) break;
                address = (IntPtr)nextAddress;
            }
            finally
            {
                Marshal.FreeHGlobal(pMbi);
            }
        }
    }

    /// <summary>
    /// Searches for a pattern in the process memory.
    /// </summary>
    /// <param name="pattern">A string pattern (space-separated) that may include wildcard tokens.</param>
    /// <param name="startAddress">The start address of the search.</param>
    /// <param name="endAddress">The end address of the search.</param>
    /// <param name="chunkSize">The size of each chunk read from the process memory.</param>
    /// <returns>A list of matching addresses.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the process is not open.</exception>
    /// <exception cref="ArgumentNullException">Thrown if the pattern is null or empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if addresses or chunk size are invalid.</exception>
    public List<IntPtr> Search(string pattern, IntPtr startAddress, IntPtr endAddress, int chunkSize = 8192)
    {
        var patternTokens = pattern.Split(' ');
        var wildcards = patternTokens.Select(token => new Wildcard(token)).ToArray();
        return Search(wildcards, startAddress, endAddress, chunkSize);
    }

    /// <summary>
    /// Searches for a wildcard pattern in the process memory.
    /// </summary>
    /// <param name="pattern">An array of <see cref="Wildcard"/> tokens.</param>
    /// <param name="startAddress">The start address of the search.</param>
    /// <param name="endAddress">The end address of the search.</param>
    /// <param name="chunkSize">The size of each chunk read from the process memory.</param>
    /// <returns>A list of matching addresses.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the process is not open.</exception>
    /// <exception cref="ArgumentNullException">Thrown if the pattern is null or empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if addresses or chunk size are invalid.</exception>
    public List<IntPtr> Search(Wildcard[] pattern, IntPtr startAddress, IntPtr endAddress, int chunkSize = 8196)
    {
        if (_processHandle == IntPtr.Zero)
            throw new InvalidOperationException($"Process with ID {_processId} is not open.");

        if (pattern == null || pattern.Length == 0)
            throw new ArgumentNullException(nameof(pattern), "The search pattern cannot be null or empty.");

        if (startAddress.ToInt64() >= endAddress.ToInt64())
            throw new ArgumentOutOfRangeException(nameof(startAddress), 
                "Start address must be less than end address.");

        if (chunkSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(chunkSize), "Chunk size must be a positive value.");

        if (pattern.Length > chunkSize)
            throw new ArgumentOutOfRangeException(nameof(pattern), "Pattern is too large for chunk size.");

        var matches = new List<IntPtr>();
        long start = startAddress.ToInt64();
        long end = endAddress.ToInt64();
        int patternLength = pattern.Length;
        long currentOffset = start;

        while (currentOffset < end)
        {
            long bytesRemaining = end - currentOffset;
            long bytesToRead = Math.Min(bytesRemaining, chunkSize + patternLength - 1);
            if (bytesToRead <= 0)
                break;

            var data = Read((IntPtr)currentOffset, (int)bytesToRead);

            for (int i = 0; i <= data.Length - patternLength; i++)
            {
                bool match = true;
                for (int j = 0; j < patternLength; j++)
                {
                    if (!pattern[j].Matches(data[i + j]))
                    {
                        match = false;
                        break;
                    }
                }
                if (match)
                {
                    matches.Add((IntPtr)(currentOffset + i));
                }
            }
            currentOffset += chunkSize;
        }
        return matches;
    }

    /// <summary>
    /// Reads a struct of type T from the specified address in the target process.
    /// </summary>
    /// <typeparam name="T">The struct type to read.</typeparam>
    /// <param name="address">The address to read from.</param>
    /// <returns>An instance of T populated with data read from memory.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the process is not open.</exception>
    public T Read<T>(IntPtr address) where T : struct
    {
        _logger.Debug("Read {Type} from 0x{Address:X16}.", typeof(T), address);
        if (_processHandle == IntPtr.Zero)
            throw new InvalidOperationException($"Process with ID {_processId} is not open.");

        int size = Marshal.SizeOf<T>();
        byte[] buffer = Read(address, size);

        GCHandle gcHandle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        try
        {
            return Marshal.PtrToStructure<T>(gcHandle.AddrOfPinnedObject());
        }
        finally
        {
            gcHandle.Free();
        }
    }

    /// <summary>
    /// Dereferences a pointer with the provided offsets.
    /// </summary>
    /// <param name="address">The initial address to start dereferencing from.</param>
    /// <param name="offsets">The offsets to walk through to find the final pointer.</param>
    /// <returns>The final pointer after applying all offsets.</returns>
    public IntPtr Dereference(IntPtr address, int[] offsets)
    {
        return offsets.Aggregate(address, (current, offset) => Read<IntPtr>(current) + offset);
    }

    /// <summary>
    /// Reads a specified number of bytes starting from the given address.
    /// </summary>
    /// <param name="address">The address to read from.</param>
    /// <param name="size">The number of bytes to read.</param>
    /// <returns>A byte array containing the data read from memory.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the process is not open.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the size is invalid.</exception>
    /// <exception cref="Win32Exception">Thrown if the read operation fails.</exception>
    /// <exception cref="InvalidOperationException">Thrown if fewer bytes are read than requested.</exception>
    public byte[] Read(IntPtr address, int size)
    {
        _logger.Debug("Read {Size} bytes from 0x{Address:X16}.", size, address);

        if (_processHandle == IntPtr.Zero)
            throw new InvalidOperationException($"Process with ID {_processId} is not open.");

        if (size <= 0)
            throw new ArgumentOutOfRangeException(nameof(size), "Size must be non-negative.");

        byte[] buffer = new byte[size];
        GCHandle gcHandle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        try
        {
            int status = NtReadVirtualMemory(
                _processHandle,
                address,
                gcHandle.AddrOfPinnedObject(),
                size,
                out int bytesRead
            );

            if (!NT_SUCCESS(status))
            {
                throw new Win32Exception(
                    $"NtReadVirtualMemory failed, NTSTATUS=0x{status:X8}, address=0x{address:X16}"
                );
            }

            if (bytesRead != size)
            {
                throw new InvalidOperationException(
                    $"Failed to read {size} bytes at 0x{address:X16}. Only {bytesRead} were read."
                );
            }
        }
        finally
        {
            gcHandle.Free();
        }

        return buffer;
    }

    /// <summary>
    /// Writes a struct of type T to the specified address in the target process.
    /// </summary>
    /// <typeparam name="T">The struct type to write.</typeparam>
    /// <param name="address">The address to write to.</param>
    /// <param name="value">The struct value to write.</param>
    /// <exception cref="InvalidOperationException">Thrown if the process is not open.</exception>
    public void Write<T>(IntPtr address, T value) where T : struct
    {
        _logger.Debug("Write {Type} to 0x{Address:X16}.", typeof(T), address);

        if (_processHandle == IntPtr.Zero)
            throw new InvalidOperationException($"Process with ID {_processId} is not open.");

        int size = Marshal.SizeOf<T>();
        byte[] buffer = new byte[size];

        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(value, ptr, false);
            Marshal.Copy(ptr, buffer, 0, size);
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }

        Write(address, buffer);
    }

    /// <summary>
    /// Writes a byte array to the specified address in the target process.
    /// </summary>
    /// <param name="address">The address to write to.</param>
    /// <param name="buffer">The data to write.</param>
    /// <exception cref="InvalidOperationException">Thrown if the process is not open.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the buffer length is invalid.</exception>
    /// <exception cref="Win32Exception">Thrown if the write operation fails.</exception>
    /// <exception cref="InvalidOperationException">Thrown if fewer bytes are written than requested.</exception>
    public void Write(IntPtr address, byte[] buffer)
    {
        _logger.Debug("Write {Size} bytes to 0x{Address:X16}.", buffer.Length, address);

        if (_processHandle == IntPtr.Zero)
            throw new InvalidOperationException($"Process with ID {_processId} is not open.");

        if (buffer.Length <= 0)
            throw new ArgumentOutOfRangeException(nameof(buffer), "Buffer must be non-negative.");

        GCHandle gcHandle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            
        try
        {
            int status = NtWriteVirtualMemory(
                _processHandle,
                address,
                gcHandle.AddrOfPinnedObject(),
                buffer.Length,
                out int bytesWritten
            );

            if (!NT_SUCCESS(status))
            {
                throw new Win32Exception(
                    $"NtWriteVirtualMemory failed, NTSTATUS=0x{status:X8}, address=0x{address:X16}"
                );
            }

            if (bytesWritten != buffer.Length)
            {
                throw new InvalidOperationException(
                    $"Failed to write {buffer.Length} bytes at 0x{address:X16}. Only {bytesWritten} were written."
                );
            }
        }
        finally
        {
            gcHandle.Free();
        }
    }

    /// <summary>
    /// Allocates memory within the target process using NtAllocateVirtualMemory.
    /// </summary>
    /// <param name="size">Number of bytes to allocate.</param>
    /// <param name="address">Optional base address to allocate at (or IntPtr.Zero for automatic).</param>
    /// <param name="allocationType">The allocation type flags.</param>
    /// <param name="protection">The memory protection flags for the allocated region.</param>
    /// <returns>An IntPtr to the base address of the newly allocated region.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the process is not open.</exception>
    /// <exception cref="Win32Exception">Thrown if allocation fails.</exception>
    public IntPtr Alloc(int size, IntPtr address = default,
        AllocationType allocationType = AllocationType.MEM_COMMIT | AllocationType.MEM_RESERVE,
        MemoryProtection protection = MemoryProtection.PAGE_READWRITE)
    {
        _logger.Debug(
            "Allocate {Size} bytes at {AddressString} with type {AllocationType} and protection {Protection}.",
            size,
            address == IntPtr.Zero ? "System Determined Address" : $"0x{address:X16}",
            allocationType,
            protection);

        if (_processHandle == IntPtr.Zero)
            throw new InvalidOperationException($"Process with ID {_processId} is not open.");

        IntPtr baseAddress = address;
        IntPtr regionSize = size;

        int status = NtAllocateVirtualMemory(
            _processHandle,
            ref baseAddress,
            IntPtr.Zero,
            ref regionSize,
            (uint)allocationType,
            (uint)protection
        );

        if (!NT_SUCCESS(status))
        {
            throw new Win32Exception(
                $"NtAllocateVirtualMemory failed, NTSTATUS=0x{status:X8}, size={size}, process={_processId}."
            );
        }

        _logger.Debug(
            "NtAllocateVirtualMemory returned base=0x{0:X16}, size={1}",
            baseAddress.ToInt64(),
            regionSize
        );

        return baseAddress;
    }

    /// <summary>
    /// Deallocates or releases memory in the target process using NtFreeVirtualMemory.
    /// </summary>
    /// <param name="address">The base address of the region to free.</param>
    /// <param name="freeType">The type of free operation (e.g., MEM_RELEASE, MEM_DECOMMIT).</param>
    /// <returns>True if the operation succeeded; otherwise, false.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the process is not open.</exception>
    /// <exception cref="Win32Exception">Thrown if freeing memory fails.</exception>
    public bool Dealloc(IntPtr address, FreeType freeType = FreeType.MEM_RELEASE)
    {
        _logger.Debug("Deallocate memory at 0x{Address:X16} with type {FreeType}.", address, freeType);

        if (_processHandle == IntPtr.Zero)
            throw new InvalidOperationException($"Process with ID {_processId} is not open.");

        IntPtr baseAddress = address;
        IntPtr regionSize = IntPtr.Zero;

        int status = NtFreeVirtualMemory(
            _processHandle,
            ref baseAddress,
            ref regionSize,
            (uint)freeType
        );

        if (!NT_SUCCESS(status))
        {
            throw new Win32Exception(
                $"NtFreeVirtualMemory failed, NTSTATUS=0x{status:X8}, address=0x{address:X16}, freeType={freeType}."
            );
        }

        return true;
    }

    /// <summary>
    /// Closes the handle to the target process.
    /// </summary>
    public void Close()
    {
        _logger.Debug("Close {ProcessId}.", _processId);

        if (_processHandle == IntPtr.Zero) return;

        CloseHandle(_processHandle);
        _processHandle = IntPtr.Zero;
    }

    /// <summary>
    /// Finalizer that disposes the object.
    /// </summary>
    ~Memory()
    {
        Dispose();
    }

    /// <summary>
    /// Disposes resources held by the class.
    /// </summary>
    public void Dispose()
    {
        Close();
        GC.SuppressFinalize(this);
    }
    
    // ReSharper disable InconsistentNaming

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        int processId
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool EnumProcessModulesEx(
        IntPtr hProcess,
        [Out] IntPtr[] lphModule,
        uint cb,
        out uint lpcbNeeded,
        uint dwFilterFlag
    );

    [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetModuleBaseName(
        IntPtr hProcess,
        IntPtr hModule,
        [Out] StringBuilder lpBaseName,
        uint nSize
    );

    [DllImport("psapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetModuleInformation(
        IntPtr hProcess,
        IntPtr hModule,
        out MODULEINFO lpmodinfo,
        uint cb
    );

    [DllImport("ntdll.dll", SetLastError = false)]
    private static extern int NtQueryVirtualMemory(
        IntPtr ProcessHandle,
        IntPtr BaseAddress,
        int MemoryInformationClass,
        IntPtr MemoryInformation,
        int MemoryInformationLength,
        out IntPtr ReturnLength
    );

    [DllImport("ntdll.dll", SetLastError = false)]
    private static extern int NtReadVirtualMemory(
        IntPtr ProcessHandle,
        IntPtr BaseAddress,
        IntPtr Buffer,
        int NumberOfBytesToRead,
        out int NumberOfBytesRead
    );

    [DllImport("ntdll.dll", SetLastError = false)]
    private static extern int NtWriteVirtualMemory(
        IntPtr ProcessHandle,
        IntPtr BaseAddress,
        IntPtr Buffer,
        int NumberOfBytesToWrite,
        out int NumberOfBytesWritten
    );

    [DllImport("ntdll.dll", SetLastError = false)]
    private static extern int NtAllocateVirtualMemory(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        IntPtr ZeroBits,
        ref IntPtr RegionSize,
        uint AllocationType,
        uint Protect
    );

    [DllImport("ntdll.dll", SetLastError = false)]
    private static extern int NtFreeVirtualMemory(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        ref IntPtr RegionSize,
        uint FreeType
    );

    // ReSharper restore InconsistentNaming
    
    /// <summary>
    /// Checks if an NTSTATUS code indicates a successful operation.
    /// </summary>
    /// <param name="status">The NTSTATUS code to check.</param>
    /// <returns>True if successful; otherwise, false.</returns>
    private static bool NT_SUCCESS(int status)
    {
        return status >= 0;
    }
}