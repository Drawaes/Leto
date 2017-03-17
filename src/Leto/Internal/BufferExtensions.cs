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

        public static void Write24BitNumber(ref WritableBuffer buffer, int numberToWrite)
        {
            buffer.Ensure(3);
            var span = buffer.Memory.Span;
            Write24BitNumber(span, numberToWrite);
            buffer.Advance(3);
        }

        public static void Write24BitNumber(this Span<byte> span, int numberToWrite)
        {
            span[0] = ((byte)(((numberToWrite & 0xFF0000) >> 16)));
            span[1] = ((byte)(((numberToWrite & 0x00ff00) >> 8)));
            span[2] = ((byte)(numberToWrite & 0x0000ff));
         }

        public static void WriteVector24Bit(ref WritableBuffer buffer, Func<WritableBuffer, WritableBuffer> contentWriter)
        {
            buffer.Ensure(3);
            var bookmark = buffer.Memory;
            buffer.Advance(3);
            int currentSize = buffer.BytesWritten;
            buffer = contentWriter(buffer);
            currentSize = buffer.BytesWritten - currentSize;
            bookmark.Span.Write24BitNumber(currentSize);
        }
    }
}
