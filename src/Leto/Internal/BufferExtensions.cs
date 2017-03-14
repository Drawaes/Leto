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

        public static int ReadBigEndian24Bit(ref Span<byte> span)
        {
            uint value = ReadBigEndian<ushort>(ref span);
            value = (value << 8) + ReadBigEndian<byte>(ref span);
            return (int) value;
        }

        public static Span<byte> ReadFixedVector(ref Span<byte> span, int size)
        {
            var newSpan = span.Slice(0, size);
            span = span.Slice(size);
            return newSpan;
        }

        public static Span<byte> ReadVector24(ref Span<byte> span)
        {
            var size = ReadBigEndian24Bit(ref span);
            return ReadFixedVector(ref span, size);
        }

        public static Span<byte> ReadVector16(ref Span<byte> span)
        {
            var size = ReadBigEndian<ushort>(ref span);
            return ReadFixedVector(ref span, size);
        }

        public static Span<byte> ReadVector8(ref Span<byte> span)
        {
            var size = ReadBigEndian<byte>(ref span);
            return ReadFixedVector(ref span, size);
        }

        public static T ReadBigEndian<T>(ref Span<byte> span) where T : struct
        {
            var value = UnsafeUtilities.Reverse(span.Read<T>());
            span = span.Slice(Unsafe.SizeOf<T>());
            return value;
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
