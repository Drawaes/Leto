using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace Leto.Tls13
{
    public static class BufferExtensions
    {
        public static ReadableBuffer SliceBigEndian<[Primitive] T>(this ReadableBuffer buffer, out T value) where T : struct
        {
            value = buffer.ReadBigEndian<T>();
            return buffer.Slice(Unsafe.SizeOf<T>());
        }

        public static unsafe void* GetPointer(this Memory<byte> buffer, out GCHandle handle)
        {
            void* ptr;
            if (buffer.TryGetPointer(out ptr))
            {
                handle = default(GCHandle);
                return ptr;
            }
            ArraySegment<byte> array;
            buffer.TryGetArray(out array);
            handle = GCHandle.Alloc(array.Array, GCHandleType.Pinned);
            ptr = (void*)IntPtr.Add(handle.AddrOfPinnedObject(), array.Offset);
            return ptr;
        }

        public static ReadableBuffer SliceVector<[Primitive]T>(ref ReadableBuffer buffer) where T : struct
        {
            uint length = 0;
            if (typeof(T) == typeof(byte) || typeof(T) == typeof(sbyte))
            {
                length = buffer.ReadBigEndian<byte>();
                buffer = buffer.Slice(sizeof(byte));
            }
            else if (typeof(T) == typeof(ushort) || typeof(T) == typeof(short))
            {
                length = buffer.ReadBigEndian<ushort>();
                buffer = buffer.Slice(sizeof(ushort));
            }
            else if (typeof(T) == typeof(uint) || typeof(T) == typeof(int))
            {
                length = buffer.ReadBigEndian<uint>();
                buffer = buffer.Slice(sizeof(uint));
            }
            else
            {
                Internal.ExceptionHelper.ThrowException(new InvalidCastException($"The type {typeof(T)} is not a primitave integer type"));
            }
            var returnBuffer = buffer.Slice(0, (int)length);
            buffer = buffer.Slice(returnBuffer.End);
            return returnBuffer;
        }

        public static int ReadBigEndian24bit(this ReadableBuffer buffer)
        {
            uint contentSize = buffer.ReadBigEndian<ushort>();
            contentSize = (contentSize << 8) + buffer.Slice(2).ReadBigEndian<byte>();
            return (int)contentSize;
        }
    }
}
