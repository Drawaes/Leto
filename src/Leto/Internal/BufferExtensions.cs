using System;
using System.IO.Pipelines;
using System.Runtime;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Leto
{
    public static class BufferExtensions
    {
        public static Span<byte> WriteBigEndian<T>(this Span<byte> span, T value) where T : struct
        {
            value = UnsafeUtilities.Reverse(value);
            span.Write(value);
            return span.Slice(Unsafe.SizeOf<T>());
        }

        public static Span<byte> WriteBigEndian<T>(this byte[] span, T value) where T : struct
        {
            value = UnsafeUtilities.Reverse(value);
            ((Span<byte>)span).Write(value);
            return span.Slice(Unsafe.SizeOf<T>());
        }

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
