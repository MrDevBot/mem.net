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
    const int Length = 0x40;

    private static unsafe void ReadTest<T>(T src, ref T dst) where T : unmanaged
    {
        var defensiveSrcCopy = src;
        var pid = Environment.ProcessId;
        using var mem = new Memlib.Memory(pid);
        mem.Open();

        var pSrc = new nint(&src);
        dst = mem.Read<T>(pSrc);

        Assert.That(src, Is.EqualTo(defensiveSrcCopy));
        Assert.That(dst, Is.EqualTo(src));
    }

    private static unsafe void WriteTest<T>(T src, ref T dst) where T : unmanaged
    {
        var defensiveSrcCopy = src;
        var pid = Environment.ProcessId;
        using var mem = new Memlib.Memory(pid);
        mem.Open();

        fixed (T* pDst = &dst)
        {
            mem.Write(new nint(pDst), src);
        }

        Assert.That(src, Is.EqualTo(defensiveSrcCopy));
        Assert.That(dst, Is.EqualTo(src));
    }

    private static unsafe void PerformReadWriteTest<T>(int length, Random rand) where T : unmanaged
    {
        Span<T> src = stackalloc T[length];
        Span<T> dst = stackalloc T[length];

        rand.NextBytes(MemoryMarshal.AsBytes(src));

        var pid = Environment.ProcessId;
        using var mem = new Memlib.Memory(pid);
        mem.Open();

        for (var i = 0; i < length; i++)
        {
            ReadTest(src[i], ref dst[i]);
        }

        dst.Clear();
        rand.NextBytes(MemoryMarshal.AsBytes(src));

        for (var i = 0; i < length; i++)
        {
            WriteTest(src[i], ref dst[i]);
        }
    }

    [Test]
    public unsafe void BasicReadWriteTest()
    {
        PerformReadWriteTest<byte>(Length, Random.Shared);
        PerformReadWriteTest<sbyte>(Length, Random.Shared);
        PerformReadWriteTest<short>(Length, Random.Shared);
        PerformReadWriteTest<ushort>(Length, Random.Shared);
        PerformReadWriteTest<int>(Length, Random.Shared);
        PerformReadWriteTest<uint>(Length, Random.Shared);
        PerformReadWriteTest<long>(Length, Random.Shared);
        PerformReadWriteTest<ulong>(Length, Random.Shared);
        PerformReadWriteTest<Int128>(Length, Random.Shared);
        PerformReadWriteTest<UInt128>(Length, Random.Shared);
        PerformReadWriteTest<Half>(Length, Random.Shared);
        PerformReadWriteTest<float>(Length, Random.Shared);
        PerformReadWriteTest<double>(Length, Random.Shared);
        PerformReadWriteTest<decimal>(Length, Random.Shared);
        PerformReadWriteTest<Vector2>(Length, Random.Shared);
        PerformReadWriteTest<Vector3>(Length, Random.Shared);
        PerformReadWriteTest<Vector4>(Length, Random.Shared);
        PerformReadWriteTest<Matrix4x4>(Length, Random.Shared);
        PerformReadWriteTest<Quaternion>(Length, Random.Shared);
    }
}
