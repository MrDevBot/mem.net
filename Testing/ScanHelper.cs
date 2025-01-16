using Memlib;
using NUnit.Framework;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Testing;
internal static class ScanHelper
{
    public static byte[] GenerateBytes(int length, Random rand)
    {
        var bytes = new byte[length];
        rand.NextBytes(bytes);
        return bytes;
    }

    public static unsafe Wildcard[] GeneratePattern(ReadOnlySpan<byte> bytes, out nint start, out nint end, Random? rand = null)
    {
        rand ??= new Random();

        fixed (byte* pb0 = bytes)
        {
            var pbn = pb0 + bytes.Length;
            start = new nint(pb0);
            end = new nint(pbn);

            // Sanity check
            fixed (byte* endInclusive = &bytes[^1])
                Trace.Assert(pbn == endInclusive + 1);

            var pattern = new Wildcard[bytes.Length];
            var unknownChance = rand.NextSingle();
            for (var offset = 0; pb0 + offset < pbn; offset++)
            {
                var isUnknown = rand.NextSingle() < unknownChance;
                if (isUnknown)
                {
                    pattern[offset] = new Wildcard();
                    continue;
                }

                var b = pb0[offset];
                var hex = b.ToString("X2");
                pattern[offset] = new Wildcard(hex);
            }

            return pattern;
        }
    }
}
