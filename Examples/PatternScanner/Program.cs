using System.Diagnostics;
using MemNet;
using Serilog;

static class Program
{
    private static ILogger Log = new LoggerConfiguration()
        .MinimumLevel.Information()
        .WriteTo.Console()
        .CreateLogger();

    public static unsafe void Main()
    {
        var processId = Process.GetProcessesByName("CS2").FirstOrDefault()!.Id;

        using var mem = new Memory(processId, Log);
        mem.Open();

        var modules = mem.Modules();
        var client = modules.First(module => module.ModuleName == "client.dll");

        IntPtr localPlayerPtr = IntPtr.Add(client.Base, 0x187B0F0); //dwLocalPlayerPawn (A2X)
        
        IntPtr startAddr = IntPtr.Subtract(localPlayerPtr, 20);
        
        var region = mem.Read(startAddr, 20 + sizeof(IntPtr) + 20);
        var ptr = mem.Read(localPlayerPtr, sizeof(IntPtr));
        
        
        Log.Information("Region: {Region}", BitConverter.ToString(region));
        Log.Information("   Ptr: {Ptr}", BitConverter.ToString(ptr));
        
        // pattern scans from multiple game restarts
        
        // FA 7F 00 00 20 00 00 00 00 00 00 80 00 00 DA 92 6C 02 00 00 40 0C ED 92 6C 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        // FA 7F 00 00 20 00 00 00 00 00 00 80 00 18 5C 96 17 02 00 00 C0 0E 3A 9A 17 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        // FA 7F 00 00 20 00 00 00 00 00 00 80 00 00 02 73 1F 02 00 00 C0 0E A7 C9 1E 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        //                                                             __ __ __ __ __ __ __ __ <- Pointer to C_CSPlayerPawn
        
        // constant values for pattern scan
        // FA 7F 00 00 20 00 00 00 00 00 00 80 00 ?? ?? ?? ?? ?? 00 00 ?0 0? ?? ?? ?? 02
        // Offset 20 for IntPtr to C_CSPlayerPawn
        
        // search for pattern in client.dll
        var results = mem.Search("FA 7F 00 00 20 00 00 00 00 00 00 80 00 ?? ?? ?? ?? ?? 00 00 ?0 0? ?? ?? ?? 02", client.Base, IntPtr.Add(client.Base, (int)client.SizeOfImage));
        
        // log located results
        foreach (var result in results)
        {
            Log.Information("Located: {Result:X}", result);
        }

        // read ptr from scan result + 20 (distance from start of pattern)
        var scannedPtr = IntPtr.Add(results.First(), 20);
        
        
        int scannedHealth = mem.Read<int>(IntPtr.Add(scannedPtr, 0x344));
        Log.Information("Scanned Health: {ScannedHealth}", scannedHealth);
        
        mem.Close();
    }

}