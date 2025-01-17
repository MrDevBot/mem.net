using Memlib;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Testing;

[TestFixture]
internal class Tests
{
    [Test]
    [Repeat(5_000)]
    public void AobGeneralTest()
    {
        const int length = 0x2000;
        var pArr = Marshal.AllocHGlobal(length);
        Span<byte> bytes;
        unsafe
        {
            bytes = new Span<byte>(pArr.ToPointer(), length);
        }

        var rand = new Random();
        rand.NextBytes(bytes);

        try
        {
            var pid = Environment.ProcessId;
            using var mem = new Memlib.Memory(pid);
            mem.Open();

            var start = rand.Next(0, bytes.Length - 1);
            var end = rand.Next(start + 1, bytes.Length);
            Trace.Assert(end - start >= 0); // Sanity check

            var pattern = ScanHelper.GeneratePattern(
                    bytes[start..end],
                    out var pb0,
                    out var pbn,
                    rand);

            var results = mem.Search(pattern, pb0, pbn);
            foreach (var address in results)
            {
                unsafe
                {
                    var offset = (int)(address - pArr);

                    for (var j = 0; j < pattern.Length; j++)
                    {
                        var patternByte = pattern[j].AsByte();
                        var matchedByte = bytes[j + offset];
                        var matches = pattern[j].Matches(matchedByte);
                        Assert.That(matches, Is.True);
                    }
                }
            }
        }
        catch (Exception)
        {
            throw;
        }
        finally
        {
            Marshal.FreeHGlobal(pArr);
        }
    }

    [Test]
    public void AobFullLengthTest()
    {
        byte[] bytes = [0xAA, 0xBB, 0xCC, 0xDD];
        const string pattern = "AA BB ?? DD";

        var pid = Environment.ProcessId;
        using var mem = new Memlib.Memory(pid);
        mem.Open();

        unsafe
        {
            fixed (byte* pb0 = bytes)
            {
                var results = mem.Search(pattern, new nint(pb0), new nint(pb0 + bytes.Length));
                Assert.That(results, Is.Not.Null);
                Assert.That(results.Count, Is.EqualTo(1));
                var pb0nint = new nint(pb0); // Can't capture fixed locals so do a little trickery
                Assert.That(results.All(p => p == pb0nint), Is.True);
            }
        }
    }

    [Test]
    public unsafe void EdgeCases()
    {
        var rand = new Random();
        using var mem = new Memlib.Memory(Environment.ProcessId);
        mem.Open();

        var bytes = new byte[1];
        var pattern = new Wildcard[] { new("??"), new("??") };
        fixed (byte* pb0 = bytes)
        {
            var pb0nint = new nint(pb0);
            Assert.Throws<ArgumentOutOfRangeException>(
                () => mem.Search(pattern, pb0nint, pb0nint));
            Assert.Throws<ArgumentException>(
                () => mem.Search(pattern, pb0nint, pb0nint + 1));
        }
    }
}