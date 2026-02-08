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
    /// Lock for thread-safe access to process handle and operations.
    /// </summary>
    private readonly object _lock = new();

    // ReSharper disable InconsistentNaming
    private const int MEMORY_BASIC_INFORMATION_CLASS = 0;
    private const uint DUPLICATE_SAME_ACCESS_NT = 0x00000002;
    private const int ProcessBasicInformation = 0;
    private const int PEB_LDR_IN_LOAD_ORDER_MODULE_LIST_OFFSET = 0x10;
    // ReSharper restore InconsistentNaming

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
    /// Opens the target process with the specified access rights using NtOpenProcess.
    /// </summary>
    /// <param name="processAccessRights">The desired access rights.</param>
    /// <exception cref="NtStatusException">Thrown if the process cannot be opened.</exception>
    public void Open(
        ProcessAccessRights processAccessRights = ProcessAccessRights.PROCESS_VM_READ |
                                                  ProcessAccessRights.PROCESS_VM_WRITE |
                                                  ProcessAccessRights.PROCESS_QUERY_INFORMATION |
                                                  ProcessAccessRights.PROCESS_VM_OPERATION)
    {
        lock (_lock)
        {
            if (_processHandle != IntPtr.Zero)
                CloseInternal();

            var clientId = new CLIENT_ID
            {
                UniqueProcess = _processId,
                UniqueThread = IntPtr.Zero
            };

            var objectAttributes = OBJECT_ATTRIBUTES.Create();

            int status = NtOpenProcess(
                out _processHandle,
                (uint)processAccessRights,
                ref objectAttributes,
                ref clientId
            );

            if (!NT_SUCCESS(status))
            {
                throw new NtStatusException(
                    status,
                    $"Failed to open process with ID {_processId}"
                );
            }

            _logger.Debug("Opened {ProcessId} with {AccessRights}.", _processId, processAccessRights);
        }
    }

    /// <summary>
    /// Uses an existing handle for the target process.
    /// </summary>
    /// <param name="existingHandle">An existing valid handle to the target process.</param>
    /// <param name="duplicate">If true (default), duplicates the handle to prevent issues if the original is closed. 
    /// If false, uses the handle directly (caller must ensure handle remains valid).</param>
    /// <exception cref="InvalidOperationException">Thrown if the process is already open.</exception>
    /// <exception cref="ArgumentException">Thrown if the provided handle is zero/invalid.</exception>
    /// <exception cref="NtStatusException">Thrown if handle duplication fails.</exception>
    public void Open(IntPtr existingHandle, bool duplicate = true)
    {
        if (existingHandle == IntPtr.Zero)
            throw new ArgumentException("Handle cannot be zero.", nameof(existingHandle));

        lock (_lock)
        {
            if (_processHandle != IntPtr.Zero)
            {
                throw new InvalidOperationException("Process already open. Close before using another handle.");
            }

            if (duplicate)
            {
                int status = NtDuplicateObject(
                    NtCurrentProcess(),
                    existingHandle,
                    NtCurrentProcess(),
                    out IntPtr duplicatedHandle,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS_NT
                );

                if (!NT_SUCCESS(status))
                {
                    throw new NtStatusException(
                        status,
                        "Failed to duplicate process handle"
                    );
                }

                _processHandle = duplicatedHandle;
                _logger.Debug("Duplicated and using handle for process {ProcessId}.", _processId);
            }
            else
            {
                _processHandle = existingHandle;
                _logger.Debug("Using existing handle for process {ProcessId} (non-duplicated).", _processId);
            }
        }
    }

    /// <summary>
    /// Retrieves a list of modules loaded by the target process by walking the PEB.
    /// </summary>
    /// <returns>A list of <see cref="ModuleInfo"/> objects.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the process is not open.</exception>
    /// <exception cref="NtStatusException">Thrown if enumeration of modules fails.</exception>
    public List<ModuleInfo> Modules()
    {
        lock (_lock)
        {
            if (_processHandle == IntPtr.Zero)
                throw new InvalidOperationException($"Process with ID {_processId} is not open.");

            // Inline QueryProcessBasicInformation
            int pbiSize = Marshal.SizeOf<PROCESS_BASIC_INFORMATION>();
            IntPtr pbiPtr = Marshal.AllocHGlobal(pbiSize);
            PROCESS_BASIC_INFORMATION pbi;

            try
            {
                int status = NtQueryInformationProcess(
                    _processHandle,
                    ProcessBasicInformation,
                    pbiPtr,
                    pbiSize,
                    out _
                );

                if (!NT_SUCCESS(status))
                {
                    throw new NtStatusException(
                        status,
                        $"Failed to query process basic information for process {_processId}"
                    );
                }

                pbi = Marshal.PtrToStructure<PROCESS_BASIC_INFORMATION>(pbiPtr);
            }
            finally
            {
                Marshal.FreeHGlobal(pbiPtr);
            }

            // Inline EnumerateModulesViaPeb
            if (pbi.PebBaseAddress == IntPtr.Zero)
                throw new InvalidOperationException("PEB base address is null");

            // Calls public Read<T>, which handles re-entrant locking
            PEB peb = Read<PEB>(pbi.PebBaseAddress);

            if (peb.Ldr == IntPtr.Zero)
                throw new InvalidOperationException("PEB_LDR_DATA pointer is null");

            PEB_LDR_DATA ldr = Read<PEB_LDR_DATA>(peb.Ldr);

            IntPtr currentEntry = ldr.InLoadOrderModuleList.Flink;
            IntPtr listHead = peb.Ldr + PEB_LDR_IN_LOAD_ORDER_MODULE_LIST_OFFSET;

            var modules = new List<ModuleInfo>();
            const int maxIterations = 1000;
            int iterations = 0;

            while (currentEntry != IntPtr.Zero && currentEntry != listHead && iterations < maxIterations)
            {
                iterations++;

                try
                {
                    LDR_DATA_TABLE_ENTRY entry = Read<LDR_DATA_TABLE_ENTRY>(currentEntry);

                    // Re-entrant call to public Read(IntPtr, int) via delegate
                    string moduleName = entry.BaseDllName.ReadString(Read);

                    if (!string.IsNullOrEmpty(moduleName))
                    {
                        modules.Add(new ModuleInfo
                        {
                            ModuleName = moduleName,
                            Base = entry.DllBase,
                            EntryPoint = entry.EntryPoint,
                            SizeOfImage = entry.SizeOfImage
                        });
                    }

                    currentEntry = entry.InLoadOrderLinks.Flink;
                }
                catch
                {
                    break;
                }
            }

            return modules;
        }
    }

    /// <summary>
    /// Enumerates memory pages in the target process.
    /// </summary>
    /// <returns>A list of <see cref="MemoryPageInformation"/> describing the process pages.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the process is not open.</exception>
    public List<MemoryPageInformation> Query()
    {
        lock (_lock)
        {
            if (_processHandle == IntPtr.Zero)
                throw new InvalidOperationException($"Process with ID {_processId} is not open.");

            var pages = new List<MemoryPageInformation>();
            var address = IntPtr.Zero;
            var sizeOfMbi = Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();

            IntPtr pMbi = Marshal.AllocHGlobal(sizeOfMbi);
            try
            {
                while (true)
                {
                    int status = NtQueryVirtualMemory(
                        _processHandle,
                        address,
                        MEMORY_BASIC_INFORMATION_CLASS,
                        pMbi,
                        sizeOfMbi,
                        out var returnedBytes
                    );

                    if (!NT_SUCCESS(status) || returnedBytes.ToInt64() == 0)
                        break;

                    MEMORY_BASIC_INFORMATION mbi = Marshal.PtrToStructure<MEMORY_BASIC_INFORMATION>(pMbi);
                    pages.Add(new MemoryPageInformation
                    {
                        BaseAddress = mbi.BaseAddress,
                        AllocationBase = mbi.AllocationBase,
                        AllocationProtect = (MemoryProtection)mbi.AllocationProtect,
                        RegionSize = (ulong)mbi.RegionSize.ToInt64(),
                        State = (MemoryState)mbi.State,
                        Protect = (MemoryProtection)mbi.Protect,
                        Type = (MemoryType)mbi.Type
                    });

                    long baseAddr = mbi.BaseAddress.ToInt64();
                    long regionSize = mbi.RegionSize.ToInt64();

                    if (baseAddr > long.MaxValue - regionSize)
                        break;

                    long nextAddress = baseAddr + regionSize;
                    address = (IntPtr)nextAddress;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(pMbi);
            }

            return pages;
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
    /// Only committed pages with readable protection are scanned.
    /// </summary>
    /// <param name="pattern">An array of <see cref="Wildcard"/> tokens.</param>
    /// <param name="startAddress">The start address of the search.</param>
    /// <param name="endAddress">The end address of the search.</param>
    /// <param name="chunkSize">The size of each chunk read from the process memory.</param>
    /// <returns>A list of matching addresses.</returns>
    public List<IntPtr> Search(Wildcard[] pattern, IntPtr startAddress, IntPtr endAddress, int chunkSize = 8192)
    {
        if (pattern == null || pattern.Length == 0)
            throw new ArgumentNullException(nameof(pattern), "The search pattern cannot be null or empty.");

        long start = startAddress.ToInt64();
        long end = endAddress.ToInt64();

        if (start >= end)
            throw new ArgumentOutOfRangeException(nameof(startAddress),
                "Start address must be less than end address.");

        if (chunkSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(chunkSize), "Chunk size must be a positive value.");

        int patternLength = pattern.Length;

        if (patternLength > chunkSize)
            throw new ArgumentOutOfRangeException(nameof(pattern), "Pattern is too large for chunk size.");
        
        var regions = (from page in Query()
                       where page.State == MemoryState.MEM_COMMIT && Readable(page.Protect)
                       let regionStart = page.BaseAddress.ToInt64()
                       let regionEnd = regionStart + (long)page.RegionSize
                       let clampedStart = Math.Max(regionStart, start)
                       let clampedEnd = Math.Min(regionEnd, end)
                       where clampedStart < clampedEnd
                       select (clampedStart, clampedEnd)).ToList();

        if (regions.Count == 0)
            return [];

        _logger.Debug("Search scanning {RegionCount} readable regions in 0x{Start:X16}–0x{End:X16}.",
            regions.Count, start, end);

        var matches = new List<IntPtr>();

        foreach (var (regionStart, regionEnd) in regions)
        {
            long offset = regionStart;
            while (offset < regionEnd)
            {
                long remaining = regionEnd - offset;

                if (patternLength - 1 > int.MaxValue - chunkSize)
                    throw new ArgumentOutOfRangeException(nameof(pattern),
                        "Pattern length is too large for safe overlap calculation.");

                int toRead = (int)Math.Min(remaining, chunkSize + patternLength - 1);
                if (toRead < patternLength)
                    break;

                byte[] data;
                try
                {
                    data = Read((IntPtr)offset, toRead);
                }
                catch (NtStatusException ex)
                {
                    _logger.Debug(
                        "Search skipping unreadable chunk at 0x{Address:X16}: NTSTATUS=0x{Status:X8}",
                        offset, ex.NtStatus);

                    if (offset > long.MaxValue - chunkSize) break;
                    offset += chunkSize;
                    continue;
                }
                catch (InvalidOperationException ex)
                {
                    _logger.Debug(
                        "Search skipping partial read at 0x{Address:X16}: {Message}",
                        offset, ex.Message);

                    if (offset > long.MaxValue - chunkSize) break;
                    offset += chunkSize;
                    continue;
                }

                for (int i = 0; i <= data.Length - patternLength; i++)
                {
                    bool match = true;
                    for (int j = 0; j < patternLength; j++)
                    {
                        if (pattern[j].Matches(data[i + j])) continue;
                        match = false;
                        break;
                    }

                    if (!match) continue;

                    if (offset > long.MaxValue - i)
                    {
                        _logger.Warning("Search address overflow at 0x{Address:X16} + {Offset}", offset, i);
                        continue;
                    }

                    matches.Add((IntPtr)(offset + i));
                }

                if (offset > long.MaxValue - chunkSize) break;
                offset += chunkSize;
            }
        }

        return matches;
    }

    /// <summary>
    /// Determines whether a page protection value permits reading.
    /// </summary>
    private static bool Readable(MemoryProtection protect)
    {
        if ((protect & MemoryProtection.PAGE_GUARD) != 0)
            return false;

        var baseProtect = protect & ~(MemoryProtection.PAGE_GUARD |
                                      MemoryProtection.PAGE_NOCACHE |
                                      MemoryProtection.PAGE_WRITECOMBINE);

        return baseProtect is MemoryProtection.PAGE_READONLY
            or MemoryProtection.PAGE_READWRITE
            or MemoryProtection.PAGE_WRITECOPY
            or MemoryProtection.PAGE_EXECUTE_READ
            or MemoryProtection.PAGE_EXECUTE_READWRITE
            or MemoryProtection.PAGE_EXECUTE_WRITECOPY;
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
        lock (_lock)
        {
            if (_processHandle == IntPtr.Zero)
                throw new InvalidOperationException($"Process with ID {_processId} is not open.");

            _logger.Debug("Read {Type} from 0x{Address:X16}.", typeof(T), address);

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
            throw new ArgumentOutOfRangeException(nameof(size), "Size must be a positive value.");

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
    /// <exception cref="ArgumentNullException">Thrown if the buffer is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the buffer is empty.</exception>
    /// <exception cref="Win32Exception">Thrown if the write operation fails.</exception>
    /// <exception cref="InvalidOperationException">Thrown if fewer bytes are written than requested.</exception>
    public void Write(IntPtr address, byte[] buffer)
    {
        _logger.Debug("Write {Size} bytes to 0x{Address:X16}.", buffer.Length, address);

        if (_processHandle == IntPtr.Zero)
            throw new InvalidOperationException($"Process with ID {_processId} is not open.");

        if (buffer is null)
            throw new ArgumentNullException(nameof(buffer), "Buffer cannot be null.");

        if (buffer.Length == 0)
            throw new ArgumentOutOfRangeException(nameof(buffer), "Buffer must not be empty.");

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
    /// <exception cref="NtStatusException">Thrown if allocation fails.</exception>
    public IntPtr Alloc(int size, IntPtr address = default,
        AllocationType allocationType = AllocationType.MEM_COMMIT | AllocationType.MEM_RESERVE,
        MemoryProtection protection = MemoryProtection.PAGE_READWRITE)
    {
        lock (_lock)
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
                throw new NtStatusException(
                    status,
                    $"NtAllocateVirtualMemory failed for size={size}, process={_processId}"
                );
            }

            _logger.Debug(
                "NtAllocateVirtualMemory returned base=0x{0:X16}, size={1}",
                baseAddress.ToInt64(), regionSize);

            return baseAddress;
        }
    }

    /// <summary>
    /// Deallocates or releases memory in the target process using NtFreeVirtualMemory.
    /// When using MEM_RELEASE, the size must be zero (the entire region is released).
    /// When using MEM_DECOMMIT, the size specifies the number of bytes to decommit.
    /// </summary>
    /// <param name="address">The base address of the region to free.</param>
    /// <param name="size">The number of bytes to free. Must be zero for MEM_RELEASE.</param>
    /// <param name="freeType">The type of free operation (e.g., MEM_RELEASE, MEM_DECOMMIT).</param>
    /// <returns>True if the operation succeeded; otherwise, false.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the process is not open.</exception>
    /// <exception cref="ArgumentException">Thrown if size is non-zero with MEM_RELEASE.</exception>
    /// <exception cref="NtStatusException">Thrown if freeing memory fails.</exception>
    public void Dealloc(IntPtr address, int size = 0, FreeType freeType = FreeType.MEM_RELEASE)
    {
        lock (_lock)
        {
            _logger.Debug("Deallocate memory at 0x{Address:X16} with type {FreeType}.", address, freeType);

            if (_processHandle == IntPtr.Zero)
                throw new InvalidOperationException($"Process with ID {_processId} is not open.");

            if (freeType == FreeType.MEM_RELEASE && size != 0)
                throw new ArgumentException("Size must be zero when using MEM_RELEASE.", nameof(size));

            IntPtr baseAddress = address;
            IntPtr regionSize = (IntPtr)size;

            int status = NtFreeVirtualMemory(
                _processHandle,
                ref baseAddress,
                ref regionSize,
                (uint)freeType
            );

            if (!NT_SUCCESS(status))
            {
                throw new NtStatusException(
                    status,
                    $"NtFreeVirtualMemory failed at address=0x{address:X16}, freeType={freeType}"
                );
            }
        }
    }

    /// <summary>
    /// Closes the handle to the target process.
    /// </summary>
    public void Close()
    {
        lock (_lock)
        {
            _logger.Debug("Close {ProcessId}.", _processId);

            if (_processHandle == IntPtr.Zero) return;

            int status = NtClose(_processHandle);
            _processHandle = IntPtr.Zero;

            if (!NT_SUCCESS(status))
            {
                _logger.Warning("NtClose returned NTSTATUS 0x{Status:X8} for process {ProcessId}.",
                    status, _processId);
            }
        }
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

    /// <summary>
    /// Returns a pseudo-handle representing the current process.
    /// NT equivalent of kernel32!GetCurrentProcess.
    /// </summary>
    private static IntPtr NtCurrentProcess() => -1;

    // ReSharper disable InconsistentNaming

    [DllImport("ntdll.dll", SetLastError = false)]
    private static extern int NtClose(IntPtr Handle);

    [DllImport("ntdll.dll", SetLastError = false)]
    private static extern int NtDuplicateObject(
        IntPtr SourceProcessHandle,
        IntPtr SourceHandle,
        IntPtr TargetProcessHandle,
        out IntPtr TargetHandle,
        uint DesiredAccess,
        uint HandleAttributes,
        uint Options
    );

    [DllImport("ntdll.dll", SetLastError = false)]
    private static extern int NtOpenProcess(
        out IntPtr ProcessHandle,
        uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes,
        ref CLIENT_ID ClientId
    );

    [DllImport("ntdll.dll", SetLastError = false)]
    private static extern int NtQueryInformationProcess(
        IntPtr ProcessHandle,
        int ProcessInformationClass,
        IntPtr ProcessInformation,
        int ProcessInformationLength,
        out int ReturnLength
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

    [DllImport("ntdll.dll", SetLastError = false)]
    private static extern int NtProtectVirtualMemory(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        ref IntPtr RegionSize,
        uint NewProtect,
        out uint OldProtect
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