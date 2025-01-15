using System.Diagnostics;
using Memlib;
using Serilog;

namespace Pattern_Scanner;

static class Program
{
    private static ILogger Log = new LoggerConfiguration()
        .MinimumLevel.Information()
        .WriteTo.Console()
        .CreateLogger();

    /// <summary>
    /// Entry point of the application.
    /// Will search for the pattern "AA B? ?? ?D" in the client.dll module of the CS2 process and log the results.
    /// </summary>
    public static void Main()
    {
        var processId = Process.GetProcessesByName("CS2").FirstOrDefault()!.Id;

        using var mem = new Memory(processId, Log);
        mem.Open();

        var modules = mem.Modules();
        
        var client = modules.First(module => module.ModuleName == "client.dll");
        var results = mem.Search("AA B? ?? ?D", client.Base, IntPtr.Add(client.Base, (int)client.SizeOfImage));
        
        foreach (var result in results)
        {
            // log the relative address and read 16 bytes from the result
            Log.Information("0x{Addr:X} {Read}", client.Base - result, BitConverter.ToString(mem.Read(result, 16)));
        }
        
        mem.Close();
    }
}