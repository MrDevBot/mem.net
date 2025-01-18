using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Testing;

[TestFixture]
internal class ReadTests
{
    private unsafe void ReadTest<T>(T src, ref T dst) where T : unmanaged
    {
        var defensiveSrcCopy = src;
        var pid = Environment.ProcessId;
        using var mem = new Memlib.Memory(pid);
        mem.Open();

        var pSrc = new nint(&src);
        dst = mem.Read<T>(pSrc);

        Assert.That(dst, Is.EqualTo(defensiveSrcCopy));
        Assert.That(dst, Is.EqualTo(src));
    }

    private unsafe void WriteTest<T>(T src, ref T dst) where T : unmanaged
    {
        var defensiveSrcCopy = src;
        var pid = Environment.ProcessId;
        using var mem = new Memlib.Memory(pid);
        mem.Open();

        fixed (T* pDst = &dst)
        {
            mem.Write(new nint(pDst), src);
        }

        Assert.That(dst, Is.EqualTo(defensiveSrcCopy));
        Assert.That(dst, Is.EqualTo(src));
    }

    [Test]
    public unsafe void ByteReadTest()
    {
        const int length = 0x40;
        Span<byte> bSrc = stackalloc byte[length];
        Span<byte> bDst = stackalloc byte[length];

        Random.Shared.NextBytes(bSrc);

        var pid = Environment.ProcessId;
        using var mem = new Memlib.Memory(pid);
        mem.Open();

        for (var i = 0; i < length; i++)
        {
            ReadTest(bSrc[i], ref bDst[i]);
        }
    }

    [Test]
    public unsafe void ByteWriteTest()
    {
        var length = 0x40;
        Span<byte> bSrc = stackalloc byte[length];
        Span<byte> bDst = stackalloc byte[length];

        var pid = Environment.ProcessId;
        using var mem = new Memlib.Memory(pid);
        mem.Open();

        for (var i = 0; i < length; i++)
        {
            WriteTest(bSrc[i], ref bDst[i]);
        }
    }
}
