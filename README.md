![logo](https://github.com/user-attachments/assets/87b29ec9-5209-4c74-adf2-ea3a448c092e)
# Memory Editing for .NET

A .NET library for interacting with the memory of external processes. This library provides functionality to open processes, read and write memory, query memory pages, enumerate modules, and allocate or deallocate memory regions.

## Features

- Open processes with specified access rights.
- Hijack an existing process handle.
- Enumerate loaded modules in the target process.
- Query memory pages using `VirtualQueryEx`.
- Read and write memory values and byte arrays.
- Pattern searching with wildcard support.
- Allocate and deallocate memory in the target process.
- Dereference pointer chains.
- Comprehensive logging using Serilog.

## Requirements

- .NET 8.0 or later.
- Serilog for logging (optional).
- Administrator privileges may be required for accessing certain processes.

## Installation

Include the `Memlib` project in your solution or build it and reference the resulting DLL in your project.
A nuget package is planned.

## Usage

### Initialization

```csharp
var memory = new Memory(processId, Log.Logger);
```

### Open a Process

```csharp
memory.Open(ProcessAccessRights.PROCESS_VM_READ |
            ProcessAccessRights.PROCESS_VM_WRITE |
            ProcessAccessRights.PROCESS_QUERY_INFORMATION |
            ProcessAccessRights.PROCESS_VM_OPERATION);
```

### Enumerate Modules

```csharp
var modules = memory.Modules();
foreach (var module in modules)
{
    Console.WriteLine($"{module.ModuleName} - Base: {module.Base}, Size: {module.SizeOfImage}");
}
```

### Query Memory Pages

```csharp
var pages = memory.Query();
foreach (var page in pages)
{
    Console.WriteLine($"Base Address: {page.BaseAddress}, Size: {page.RegionSize}");
}
```

### Read Memory

```csharp
var value = memory.Read<int>(address);
Console.WriteLine($"Value: {value}");
```

### Write Memory

```csharp
memory.Write(address, 12345);
```

### Allocate Memory

```csharp
var allocatedAddress = memory.Alloc(1024);
Console.WriteLine($"Allocated Address: {allocatedAddress}");
```

### Deallocate Memory

```csharp
memory.Dealloc(allocatedAddress);
```

### Pattern Search

```csharp
var matches = memory.Search("AA BB ?? DD", startAddress, endAddress);
foreach (var match in matches)
{
    Console.WriteLine($"Match found at: {match}");
}
```

## Logging

This library uses [Serilog](https://serilog.net/) for logging. You can provide your own logger or use the default `Log.Logger` instance. Debug logs are generated for all operations.

## How to contribute

1. Fork the repository.
2. Create a new branch.
3. Make your changes.
4. Submit a pull request.

## License

[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

## Disclaimer

This library interacts with external processes and memory. Misuse can result in application crashes, system instability, or unintended behavior. Use responsibly and ensure you comply with all relevant laws and regulations.
