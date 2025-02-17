using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using MemNet.Enum;
using MemNet.Enum.Managed;
using MemNet.Native;
using Serilog;

namespace MemNet;

/// <summary>
/// A class for reading and writing to the memory of another process.
/// </summary>
public sealed class Memory : IDisposable
{
    private IntPtr _processHandle = IntPtr.Zero;
    private readonly int _processId;
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="Memory"/> class.
    /// </summary>
    /// <param name="processId">The ID of the target process.</param>
    /// <param name="logger">An optional logger to use for diagnostic messages.</param>
    public Memory(int processId, ILogger? logger = null)
    {
        _logger = logger ?? Log.Logger;
        _processId = processId;
    }

    /// <summary>
    /// Opens the target process with the necessary permissions.
    /// </summary>
    /// <exception cref="Win32Exception">Thrown if opening the process fails.</exception>
    public void Open(
        ProcessAccessRights processAccessRights = ProcessAccessRights.PROCESS_VM_READ |
                                                  ProcessAccessRights.PROCESS_VM_WRITE |
                                                  ProcessAccessRights.PROCESS_QUERY_INFORMATION |
                                                  ProcessAccessRights.PROCESS_VM_OPERATION)
    {
        if (_processHandle != IntPtr.Zero) Close();

        _processHandle = OpenProcess((uint)processAccessRights, false, _processId);

        _logger.Debug("Opened {ProcessId} with {AccessRights}.", _processId, processAccessRights);

        if (_processHandle == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"Failed to open process with ID {_processId}.");
    }

    /// <summary>
    /// Hijacks an existing process handle.
    /// </summary>
    /// <param name="existingHandle">The existing handle to the target process.</param>
    /// <exception cref="InvalidOperationException">Thrown if the process is already open.</exception>
    public void Open(IntPtr existingHandle)
    {
        _processHandle = existingHandle;

        _logger.Debug("Hijacked handle for process {ProcessId}.", _processId);
    }


    /// <summary>
    /// Retrieves a dictionary of loaded modules and their information in the target process.
    /// </summary>
    /// <returns>A dictionary where the key is the module name and the value is the module information.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the process is not open.</exception>
    /// <exception cref="Win32Exception">Thrown if retrieving module information fails.</exception>
    public List<ModuleInfo> Modules()
    {
        if (_processHandle == IntPtr.Zero)
            throw new InvalidOperationException($"Process with ID {_processId} is not open.");

        var modules = new List<ModuleInfo>();
        IntPtr[] moduleHandles = new IntPtr[1024];
        uint cb = (uint)(IntPtr.Size * moduleHandles.Length);

        // const uint LIST_MODULES_ALL = 0x03;

        if (!EnumProcessModulesEx(_processHandle, moduleHandles, cb, out var lpcbNeeded, 0x03))
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"Failed to enumerate process modules for process {_processId}.");

        int numModules = (int)(lpcbNeeded / (uint)IntPtr.Size);

        for (int i = 0; i < numModules; i++)
        {
            StringBuilder moduleName = new StringBuilder(256);
            if (GetModuleBaseName(_processHandle, moduleHandles[i], moduleName, (uint)moduleName.Capacity) == 0)
                continue;

            if (GetModuleInformation(_processHandle, moduleHandles[i], out MODULEINFO moduleInfo, (uint)Marshal.SizeOf<MODULEINFO>()))
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
    /// Enumerates memory pages in the target process, returning a managed
    /// <see cref="MemoryPageInformation"/> for each region.
    /// </summary>
    /// <returns>An enumeration of <see cref="MemoryPageInformation"/> instances.</returns>
    /// <remarks>
    /// This uses <see cref="VirtualQueryEx"/> in a loop until no more regions can be queried.
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// Thrown if the process is not open.
    /// </exception>
    public IEnumerable<MemoryPageInformation> Query()
    {
        if (_processHandle == IntPtr.Zero)
            throw new InvalidOperationException($"Process with ID {_processId} is not open.");

        var address = IntPtr.Zero;

        while (true)
        {
            // avoid exposing raw fields
            MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();

            IntPtr result = VirtualQueryEx(
                _processHandle,
                address,
                out mbi,
                Marshal.SizeOf(mbi)
            );

            if (result == IntPtr.Zero)
                break; // No more pages to query or end of address space

            // Convert to our managed type
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
            if (nextAddress < 0)
                break; // Overflow or invalid next address

            address = (IntPtr)nextAddress;
        }
    }

    /// <summary>
    /// Contains information about a memory page in the target process.
    /// A managed representation of the MEMORY_BASIC_INFORMATION structure.
    /// </summary>
    public sealed class MemoryPageInformation
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public MemoryProtection AllocationProtect;
        public ulong RegionSize;
        public MemoryState State;
        public MemoryProtection Protect;
        public MemoryType Type;
    }

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

    /// <summary>
    /// Searches for the specified pattern within the memory of the target process using a simple sliding window.
    /// </summary>
    /// <param name="pattern">The pattern to search for, in the format "AA BB CC ?? DD". Null bytes act as wildcards. Partial wildcard support is not implemented.</param>
    /// <param name="startAddress">The address to start the search from.</param>
    /// <param name="endAddress">The address to end the search at.</param>
    /// <param name="chunkSize">How many bytes to move forward on each iteration.</param>
    /// <returns>A list of memory addresses where the pattern was found.</returns>
    public List<IntPtr> Search(string pattern, IntPtr startAddress, IntPtr endAddress, int chunkSize = 8196)
    {
        var patternTokens = pattern.Split(' ');
        var wildcards = patternTokens.Select(token => new Wildcard(token)).ToArray();
        return Search(wildcards, startAddress, endAddress, chunkSize);
    }

    /// <summary>
    /// Searches for the specified pattern within the memory of the target process using a simple sliding window.
    /// Null bytes in the pattern act as wildcards.
    /// </summary>
    /// <param name="pattern">The byte pattern to search for. Null bytes act as wildcards.</param>
    /// <param name="startAddress">The address to start the search from.</param>
    /// <param name="endAddress">The address to end the search at.</param>
    /// <param name="chunkSize">How many bytes to move forward on each iteration.</param>
    /// <returns>A list of memory addresses where the pattern was found.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the process is not open.</exception>
    /// <exception cref="ArgumentNullException">Thrown if the pattern is null or empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if startAddress is greater than or equal to endAddress.</exception>
    public List<IntPtr> Search(Wildcard[] pattern, IntPtr startAddress, IntPtr endAddress, int chunkSize = 8196)
    {
        if (_processHandle == IntPtr.Zero)
            throw new InvalidOperationException($"Process with ID {_processId} is not open.");

        if (pattern == null || pattern.Length == 0)
            throw new ArgumentNullException(nameof(pattern), "The search pattern cannot be null or empty.");

        if (startAddress.ToInt64() >= endAddress.ToInt64())
            throw new ArgumentOutOfRangeException(nameof(startAddress), "Start address must be less than end address.");

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
                var match = true;
                for (int j = 0; j < patternLength; j++)
                {
                    if (pattern[j].Matches(data[i + j])) continue;
                    
                    match = false;
                    break;
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
    /// Reads a value of type T from the specified memory address in the target process.
    /// </summary>
    /// <typeparam name="T">The type of the value to read.</typeparam>
    /// <param name="address">The memory address to read from.</param>
    /// <returns>The value read from memory.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the process is not open.</exception>
    /// <exception cref="Win32Exception">Thrown if reading memory fails.</exception>
    public T Read<T>(IntPtr address) where T : struct
    {
        _logger.Debug("Read {Type} from 0x{Address:X16}.", typeof(T), address);

        if (_processHandle == IntPtr.Zero)
            throw new InvalidOperationException($"Process with ID {_processId} is not open.");

        int size = Marshal.SizeOf<T>();
        byte[] buffer = new byte[size];

        if (!ReadProcessMemory(_processHandle, address, buffer, size, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                $"Failed to read memory from address 0x{address:X16} in process {_processId}.");

        return Marshal.PtrToStructure<T>(Marshal.UnsafeAddrOfPinnedArrayElement(buffer, 0));
    }
    
    /// <summary>
    /// Dereferences a pointer chain in the target process.
    /// </summary>
    /// <param name="address">The base address to start from.</param>
    /// <param name="offsets">An array of offsets to follow.</param>
    /// <returns>Dereferenced pointer</returns>
    public IntPtr Dereference(IntPtr address, int[] offsets)
    {
        return offsets.Aggregate(address, (current, offset) => Read<IntPtr>(current) + offset);
    }
    
    /// <summary>
    /// Reads a specified number of bytes from the specified memory address in the target process.
    /// </summary>
    /// <param name="address">The memory address to read from.</param>
    /// <param name="size">The number of bytes to read.</param>
    /// <returns></returns>
    /// <exception cref="InvalidOperationException">Thrown if the process is not open.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the size is 0 or negative.</exception>
    /// <exception cref="Win32Exception">Thrown if reading memory fails.</exception>
    public byte[] Read(IntPtr address, int size)
    {
        _logger.Debug("Read {Size} bytes from 0x{Address:X16}.", size, address);

        if (_processHandle == IntPtr.Zero)
            throw new InvalidOperationException($"Process with ID {_processId} is not open.");


        if (size <= 0)
            throw new ArgumentOutOfRangeException(nameof(size), "Size must be non-negative.");

        byte[] buffer = new byte[size];

        if (!ReadProcessMemory(_processHandle, address, buffer, size, out var bytesRead))
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                $"Failed to read {size} bytes from address 0x{address:X16} in process {_processId}.");

        if (bytesRead.ToInt64() != size)
        {
            throw new InvalidOperationException(
                $"Failed to read {size} bytes from address 0x{address:X16} in process {_processId}. " +
                $"Only {bytesRead.ToInt64()} bytes were read.");
            // Array.Resize(ref buffer, bytesRead.ToInt64());
        }

        return buffer;
    }

    /// <summary>
    /// Writes a value of type T to the specified memory address in the target process.
    /// </summary>
    /// <typeparam name="T">The type of the value to write.</typeparam>
    /// <param name="address">The memory address to write to.</param>
    /// <param name="value">The value to write.</param>
    /// <exception cref="InvalidOperationException">Thrown if the process is not open.</exception>
    /// <exception cref="Win32Exception">Thrown if writing memory fails.</exception>
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

        if (!WriteProcessMemory(_processHandle, address, buffer, size, out _))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                $"Failed to write memory to address 0x{address:X16} in process {_processId}.");
        }
    }

    /// <summary>
    /// Writes the specified buffer to the specified memory address in the target process.
    /// </summary>
    /// <param name="address">The memory address to write to.</param>
    /// <param name="buffer">The buffer to write.</param>
    /// <returns>The buffer that was written.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the process is not open.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the buffer is empty.</exception>
    /// <exception cref="Win32Exception">Thrown if writing memory fails.</exception>
    public byte[] Write(IntPtr address, byte[] buffer)
    {
        _logger.Debug("Write {Size} bytes to 0x{Address:X16}.", buffer.Length, address);

        if (_processHandle == IntPtr.Zero)
            throw new InvalidOperationException($"Process with ID {_processId} is not open.");

        if (buffer.Length <= 0)
            throw new ArgumentOutOfRangeException(nameof(buffer), "Buffer must be non-negative.");

        if (!WriteProcessMemory(_processHandle, address, buffer, buffer.Length, out var bytesWritten))
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                $"Failed to write {buffer.Length} bytes to address 0x{address:X16} in process {_processId}.");

        if (bytesWritten.ToInt64() != buffer.Length)
        {
            throw new InvalidOperationException(
                $"Failed to write {buffer.Length} bytes to address 0x{address:X16} in process {_processId}. " +
                $"Only {bytesWritten.ToInt64()} bytes were written.");
            // Array.Resize(ref buffer, bytesWritten.ToInt64());
        }

        return buffer;
    }

    /// <summary>
    /// Allocates a region of memory within the virtual address space of the target process.
    /// </summary>
    /// <param name="size">The size of the memory region to allocate, in bytes.</param>
    /// <param name="address">The desired starting address for the allocation. If <see cref="IntPtr.Zero"/>, the system determines the address.</param>
    /// <param name="allocationType">The type of memory allocation.</param>
    /// <param name="protection">The memory protection for the region of pages to be allocated.</param>
    /// <returns>The base address of the allocated region of pages.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the process is not open.</exception>
    /// <exception cref="Win32Exception">Thrown if the allocation fails.</exception>
    public IntPtr Alloc(int size, IntPtr address = default,
        AllocationType allocationType = AllocationType.MEM_COMMIT | AllocationType.MEM_RESERVE,
        MemoryProtection protection = MemoryProtection.PAGE_READWRITE)
    {
        _logger.Debug(
            "Allocate {Size} bytes at {AddressString} with type {AllocationType} and protection {Protection}.",
            size, address == IntPtr.Zero ? "System Determined Address" : $"0x{address:X16}", allocationType,
            protection);

        if (_processHandle == IntPtr.Zero)
            throw new InvalidOperationException($"Process with ID {_processId} is not open.");

        IntPtr result = VirtualAllocEx(_processHandle, address, (uint)size, (uint)allocationType, (uint)protection);

        if (result == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                $"Failed to allocate {size} bytes in process {_processId}.");

        _logger.Debug("Allocated memory at 0x{Result:X16}.", result);
        return result;
    }

    /// <summary>
    /// Deallocates a region of memory previously allocated in the target process.
    /// </summary>
    /// <param name="address">A pointer to the base address of the memory block to be freed.</param>
    /// <param name="freeType">The type of free operation. Defaults to <see cref="FreeType.MEM_RELEASE"/>.</param>
    /// <returns><c>true</c> if the function succeeds; otherwise, <c>false</c>.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the process is not open.</exception>
    /// <exception cref="Win32Exception">Thrown if the deallocation fails.</exception>
    public bool Dealloc(IntPtr address, FreeType freeType = FreeType.MEM_RELEASE)
    {
        _logger.Debug("Deallocate memory at 0x{Address:X16} with type {FreeType}.", address, freeType);

        if (_processHandle == IntPtr.Zero)
            throw new InvalidOperationException($"Process with ID {_processId} is not open.");

        bool result = VirtualFreeEx(_processHandle, address, 0, (uint)freeType);

        if (!result)
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                $"Failed to deallocate memory at 0x{address:X16} in process {_processId}.");

        return result;
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
    /// Finalizes an instance of the <see cref="Memory"/> class.
    /// </summary>
    ~Memory()
    {
        Dispose();
    }

    /// <summary>
    /// Releases all resources used by the <see cref="Memory"/> object.
    /// </summary>
    public void Dispose()
    {
        // release the handle
        Close();

        GC.SuppressFinalize(this);
    }

    // ReSharper disable InconsistentNaming
    // ReSharper disable UnusedMember.Local

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer,
        int dwSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize,
        out IntPtr lpNumberOfBytesWritten);

    /*
    [DllImport("psapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumProcessModules(IntPtr hProcess, [Out] IntPtr[] lphModule, uint cb,
        [MarshalAs(UnmanagedType.U4)] out uint lpcbNeeded);
    */
    
    [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule, uint cb, 
        out uint lpcbNeeded, uint dwFilterFlag);

    [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetModuleBaseName(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName,
        uint nSize);

    [DllImport("psapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out MODULEINFO lpmodinfo, uint cb);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType,
        uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);

    // New: VirtualQueryEx import.
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION lpBuffer, IntPtr dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetHandleInformation(IntPtr hObject, out uint lpdwFlags);
}