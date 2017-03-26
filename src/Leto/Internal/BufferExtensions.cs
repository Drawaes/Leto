using System;
using System.Binary;
using System.Buffers;
using System.IO.Pipelines;
using System.Runtime;
using System.Runtime.CompilerServices;

namespace Leto
{
    public static class BufferExtensions
    {
        public static unsafe T Reverse<[Primitive]T>(T value) where T : struct
        {
            // note: relying on JIT goodness here!
            if (typeof(T) == typeof(byte) || typeof(T) == typeof(sbyte))
            {
                return value;
            }
            else if (typeof(T) == typeof(ushort) || typeof(T) == typeof(short))
            {
                ushort val = 0;
                Unsafe.Write(&val, value);
                val = (ushort)((val >> 8) | (val << 8));
                return Unsafe.Read<T>(&val);
            }
            else if (typeof(T) == typeof(uint) || typeof(T) == typeof(int)
                || typeof(T) == typeof(float))
            {
                uint val = 0;
                Unsafe.Write(&val, value);
                val = (val << 24)
                    | ((val & 0xFF00) << 8)
                    | ((val & 0xFF0000) >> 8)
                    | (val >> 24);
                return Unsafe.Read<T>(&val);
            }
            else if (typeof(T) == typeof(ulong) || typeof(T) == typeof(long)
                || typeof(T) == typeof(double))
            {
                ulong val = 0;
                Unsafe.Write(&val, value);
                val = (val << 56)
                    | ((val & 0xFF00) << 40)
                    | ((val & 0xFF0000) << 24)
                    | ((val & 0xFF000000) << 8)
                    | ((val & 0xFF00000000) >> 8)
                    | ((val & 0xFF0000000000) >> 24)
                    | ((val & 0xFF000000000000) >> 40)
                    | (val >> 56);
                return Unsafe.Read<T>(&val);
            }
            else
            {
                // default implementation
                int len = Unsafe.SizeOf<T>();
                var val = stackalloc byte[len];
                Unsafe.Write(val, value);
                int to = len >> 1, dest = len - 1;
                for (int i = 0; i < to; i++)
                {
                    var tmp = val[i];
                    val[i] = val[dest];
                    val[dest--] = tmp;
                }
                return Unsafe.Read<T>(val);
            }
        }

        public static Span<byte> WriteBigEndian<T>(this Span<byte> span, T value) where T : struct
        {
            value = Reverse(value);
            span.Write(value);
            return span.Slice(Unsafe.SizeOf<T>());
        }

        public static Span<byte> WriteBigEndian<T>(this byte[] span, T value) where T : struct
        {
            value = Reverse(value);
            ((Span<byte>)span).Write(value);
            return span.Slice(Unsafe.SizeOf<T>());
        }

        public static int ReadBigEndian24Bit(ref Span<byte> span)
        {
            uint value = ReadBigEndian<ushort>(ref span);
            value = (value << 8) + ReadBigEndian<byte>(ref span);
            return (int)value;
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
            var value = Reverse(span.Read<T>());
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
            var span = buffer.Buffer.Span;
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
            var bookmark = buffer.Buffer;
            buffer.Advance(3);
            int currentSize = buffer.BytesWritten;
            buffer = contentWriter(buffer);
            currentSize = buffer.BytesWritten - currentSize;
            bookmark.Span.Write24BitNumber(currentSize);
        }

        public static void WriteVector<[Primitive] T>(ref WritableBuffer buffer, Func<WritableBuffer, WritableBuffer> writeContent) where T : struct
        {
            var bookMark = buffer.Buffer;
            if (typeof(T) == typeof(ushort) || typeof(T) == typeof(short))
            {
                buffer.WriteBigEndian((ushort)0);
            }
            else if (typeof(T) == typeof(byte))
            {
                buffer.WriteBigEndian((byte)0);
            }
            else
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.internal_error, $"Unkown vector type {typeof(T).Name}");
            }
            var sizeofVector = buffer.BytesWritten;
            buffer = writeContent(buffer);
            sizeofVector = buffer.BytesWritten - sizeofVector;
            if (typeof(T) == typeof(ushort) || typeof(T) == typeof(short))
            {
                bookMark.Span.WriteBigEndian((ushort)sizeofVector);
            }
            else
            {
                bookMark.Span.Write((byte)sizeofVector);
            }
        }

        public static Buffer<byte> SliceAndConsume(ref Buffer<byte> buffer, int size)
        {
            var returnBuffer = buffer.Slice(0, size);
            buffer = buffer.Slice(size);
            return returnBuffer;
        }
    }
}
