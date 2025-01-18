using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Testing;

[TestFixture]
internal class ReadWriteTests
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

    [Test]
    public unsafe void ShortReadTest()
    {
        const int length = 0x40;
        Span<short> sSrc = stackalloc short[length];
        Span<short> sDst = stackalloc short[length];
        Random.Shared.NextBytes(MemoryMarshal.AsBytes(sSrc));
        var pid = Environment.ProcessId;
        using var mem = new Memlib.Memory(pid);
        mem.Open();
        for (var i = 0; i < length; i++)
        {
            ReadTest(sSrc[i], ref sDst[i]);
        }
    }

    [Test]
    public unsafe void ShortWriteTest()
    {
        const int length = 0x40;
        Span<short> sSrc = stackalloc short[length];
        Span<short> sDst = stackalloc short[length];
        Random.Shared.NextBytes(MemoryMarshal.AsBytes(sSrc));
        var pid = Environment.ProcessId;
        using var mem = new Memlib.Memory(pid);
        mem.Open();
        for (var i = 0; i < length; i++)
        {
            WriteTest(sSrc[i], ref sDst[i]);
        }
    }

    [Test]
    public unsafe void IntReadTest()
    {
        const int length = 0x40;
        Span<int> iSrc = stackalloc int[length];
        Span<int> iDst = stackalloc int[length];
        Random.Shared.NextBytes(MemoryMarshal.AsBytes(iSrc));
        var pid = Environment.ProcessId;
        using var mem = new Memlib.Memory(pid);
        mem.Open();
        for (var i = 0; i < length; i++)
        {
            ReadTest(iSrc[i], ref iDst[i]);
        }
    }

    [Test]
    public unsafe void LongReadTest()
    {
        const int length = 0x40;
        Span<long> lSrc = stackalloc long[length];
        Span<long> lDst = stackalloc long[length];
        Random.Shared.NextBytes(MemoryMarshal.AsBytes(lSrc));
        var pid = Environment.ProcessId;
        using var mem = new Memlib.Memory(pid);
        mem.Open();
        for (var i = 0; i < length; i++)
        {
            ReadTest(lSrc[i], ref lDst[i]);
        }
    }

    [Test]
    public unsafe void LongWriteTest()
    {
        const int length = 0x40;
        Span<long> lSrc = stackalloc long[length];
        Span<long> lDst = stackalloc long[length];
        Random.Shared.NextBytes(MemoryMarshal.AsBytes(lSrc));
        var pid = Environment.ProcessId;
        using var mem = new Memlib.Memory(pid);
        mem.Open();
        for (var i = 0; i < length; i++)
        {
            WriteTest(lSrc[i], ref lDst[i]);
        }
    }

    [Test]
    public unsafe void Int128ReadTest()
    {
        const int length = 0x40;
        Span<Int128> i128Src = stackalloc Int128[length];
        Span<Int128> i128Dst = stackalloc Int128[length];
        Random.Shared.NextBytes(MemoryMarshal.AsBytes(i128Src));
        var pid = Environment.ProcessId;
        using var mem = new Memlib.Memory(pid);
        mem.Open();
        for (var i = 0; i < length; i++)
        {
            ReadTest(i128Src[i], ref i128Dst[i]);
        }
    }

    [Test]
    public unsafe void Int128WriteTest()
    {
        const int length = 0x40;
        Span<Int128> i128Src = stackalloc Int128[length];
        Span<Int128> i128Dst = stackalloc Int128[length];
        Random.Shared.NextBytes(MemoryMarshal.AsBytes(i128Src));
        var pid = Environment.ProcessId;
        using var mem = new Memlib.Memory(pid);
        mem.Open();
        for (var i = 0; i < length; i++)
        {
            WriteTest(i128Src[i], ref i128Dst[i]);
        }
    }

    [Test]
    public unsafe void FloatReadTest()
    {
        const int length = 0x40;
        Span<float> fSrc = stackalloc float[length];
        Span<float> fDst = stackalloc float[length];
        Random.Shared.NextBytes(MemoryMarshal.AsBytes(fSrc));
        var pid = Environment.ProcessId;
        using var mem = new Memlib.Memory(pid);
        mem.Open();
        for (var i = 0; i < length; i++)
        {
            ReadTest(fSrc[i], ref fDst[i]);
        }
    }

    [Test]
    public unsafe void FloatWriteTest()
    {
        const int length = 0x40;
        Span<float> fSrc = stackalloc float[length];
        Span<float> fDst = stackalloc float[length];
        Random.Shared.NextBytes(MemoryMarshal.AsBytes(fSrc));
        var pid = Environment.ProcessId;
        using var mem = new Memlib.Memory(pid);
        mem.Open();
        for (var i = 0; i < length; i++)
        {
            WriteTest(fSrc[i], ref fDst[i]);
        }
    }

    [Test]
    public unsafe void DoubleReadTest()
    {
        const int length = 0x40;
        Span<double> dSrc = stackalloc double[length];
        Span<double> dDst = stackalloc double[length];
        Random.Shared.NextBytes(MemoryMarshal.AsBytes(dSrc));
        var pid = Environment.ProcessId;
        using var mem = new Memlib.Memory(pid);
        mem.Open();
        for (var i = 0; i < length; i++)
        {
            ReadTest(dSrc[i], ref dDst[i]);
        }
    }

    [Test]
    public unsafe void DoubleWriteTest()
    {
        const int length = 0x40;
        Span<double> dSrc = stackalloc double[length];
        Span<double> dDst = stackalloc double[length];
        Random.Shared.NextBytes(MemoryMarshal.AsBytes(dSrc));
        var pid = Environment.ProcessId;
        using var mem = new Memlib.Memory(pid);
        mem.Open();
        for (var i = 0; i < length; i++)
        {
            WriteTest(dSrc[i], ref dDst[i]);
        }
    }

    [Test]
    public unsafe void DecimalReadTest()
    {
        const int length = 0x40;
        Span<decimal> decSrc = stackalloc decimal[length];
        Span<decimal> decDst = stackalloc decimal[length];
        Random.Shared.NextBytes(MemoryMarshal.AsBytes(decSrc));
        var pid = Environment.ProcessId;
        using var mem = new Memlib.Memory(pid);
        mem.Open();
        for (var i = 0; i < length; i++)
        {
            ReadTest(decSrc[i], ref decDst[i]);
        }
    }

    [Test]
    public unsafe void DecimalWriteTest() 
    {
        var length = 0x40;
        Span<decimal> decSrc = stackalloc decimal[length];
        Span<decimal> decDst = stackalloc decimal[length];
        Random.Shared.NextBytes(MemoryMarshal.AsBytes(decSrc));
        var pid = Environment.ProcessId;
        using var mem = new Memlib.Memory(pid);
        mem.Open();
        for (var i = 0; i < length; i++)
        {
            WriteTest(decSrc[i], ref decDst[i]);
        }
    }

    [Test]
    public unsafe void Vector3ReadTest()
    {
        const int length = 0x40;
        Span<Vector3> v3Src = stackalloc Vector3[length];
        Span<Vector3> v3Dst = stackalloc Vector3[length];
        Random.Shared.NextBytes(MemoryMarshal.AsBytes(v3Src));
        var pid = Environment.ProcessId;
        using var mem = new Memlib.Memory(pid);
        mem.Open();
        for (var i = 0; i < length; i++)
        {
            ReadTest(v3Src[i], ref v3Dst[i]);
        }
    }

    [Test]
    public unsafe void Vector3WriteTest()
    {
        const int length = 0x40;
        Span<Vector3> v3Src = stackalloc Vector3[length];
        Span<Vector3> v3Dst = stackalloc Vector3[length];
        Random.Shared.NextBytes(MemoryMarshal.AsBytes(v3Src));
        var pid = Environment.ProcessId;
        using var mem = new Memlib.Memory(pid);
        mem.Open();
        for (var i = 0; i < length; i++)
        {
            WriteTest(v3Src[i], ref v3Dst[i]);
        }
    }

    [Test]
    public unsafe void ManagedStructReadTest()
    {
        const int length = 0x40;
        Span<Matrix4x4> m4Src = stackalloc Matrix4x4[length];
        Span<Matrix4x4> m4Dst = stackalloc Matrix4x4[length];
        Random.Shared.NextBytes(MemoryMarshal.AsBytes(m4Src));
        var pid = Environment.ProcessId;
        using var mem = new Memlib.Memory(pid);
        mem.Open();
        for (var i = 0; i < length; i++)
        {
            ReadTest(m4Src[i], ref m4Dst[i]);
        }
    }

    [Test]
    public unsafe void ManagedStructWriteTest()
    {
        const int length = 0x40;
        Span<Matrix4x4> m4Src = stackalloc Matrix4x4[length];
        Span<Matrix4x4> m4Dst = stackalloc Matrix4x4[length];
        Random.Shared.NextBytes(MemoryMarshal.AsBytes(m4Src));
        var pid = Environment.ProcessId;
        using var mem = new Memlib.Memory(pid);
        mem.Open();
        for (var i = 0; i < length; i++)
        {
            WriteTest(m4Src[i], ref m4Dst[i]);
        }
    }
}
