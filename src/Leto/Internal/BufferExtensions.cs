using System;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Leto
{
    public static class BufferExtensions
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static Span<byte> ToSpan(this ReadableBuffer buffer)
        {
            if (buffer.IsSingleSpan)
            {
                return buffer.First.Span;
            }
            return buffer.ToArray();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static (T value, Span<byte> outBuffer) Consume<T>(this Span<byte> buffer) where T : struct
        {
            return (buffer.Read<T>(), buffer.Slice(Unsafe.SizeOf<T>()));
        }       
    }
}
