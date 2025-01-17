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
    [Test]
    public unsafe void ByteReadTest()
    {
        var length = sizeof(Int128);
        Span<byte> bx = stackalloc byte[length];

        var pid = Environment.ProcessId;
        using var mem = new Memlib.Memory(pid);
        mem.Open();

        for (var i = 0; i < length; i++)
            bx[i] = (byte)i;

        fixed (byte* pbx = bx)
        {
            for (var offset = 0; offset < length; offset++)
            {
                var addr = new nint(pbx + offset);
                var b = mem.Read<byte>(addr);
                Assert.That(b, Is.EqualTo(bx[offset]));
            }
        }
    }

    [Test]
    public unsafe void ByteWriteTest()
    {
        var length = sizeof(Int128);
        Span<byte> bSrc = stackalloc byte[length];
        Span<byte> bDst = stackalloc byte[length];

        var pid = Environment.ProcessId;
        using var mem = new Memlib.Memory(pid);
        mem.Open();

        for (var i = 0; i < length; i++)
            bSrc[i] = (byte)i;

        fixed (byte* pbDst = bSrc)
        {
            for (var offset = 0; offset < length; offset++)
            {
                var addr = new nint(pbDst + offset);
                mem.Write(addr, bSrc[offset]);
            }
        }

        for (var i = 0; i < length; i++)
            Assert.That(bDst[i], Is.EqualTo(bSrc[i]));
    }
}
