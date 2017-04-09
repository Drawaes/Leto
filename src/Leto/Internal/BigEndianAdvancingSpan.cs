using System;
using System.Binary;
using System.Collections.Generic;
using System.Runtime;
using System.Runtime.CompilerServices;
using System.Text;

namespace Leto.Internal
{
    public struct BigEndianAdvancingSpan
    {
        private Span<byte> _internalSpan;

        private static readonly bool _needsToBeReversed = BitConverter.IsLittleEndian;
        
        public BigEndianAdvancingSpan(Span<byte> span)
        {
            _internalSpan = span;
        }

        public int Length => _internalSpan.Length;

        public T Read<T>() where T : struct
        {
            var size = Unsafe.SizeOf<T>();
            var returnValue = _internalSpan.Read<T>();
            _internalSpan = _internalSpan.Slice(size);
            if (_needsToBeReversed) returnValue = BufferExtensions.Reverse(returnValue);
            return returnValue;
        }

        public Span<byte> ToSpan() => _internalSpan;
        public byte[] ToArray() => _internalSpan.ToArray();
            
        public void Write<T>(T value) where T :struct
        {
            var size = Unsafe.SizeOf<T>();
            if (_needsToBeReversed) value = BufferExtensions.Reverse(value);
            _internalSpan.Write(value);
            _internalSpan = _internalSpan.Slice(size);
        }
           
        public void CopyFrom(ReadOnlySpan<byte> span)
        {
            span.CopyTo(_internalSpan);
            _internalSpan = _internalSpan.Slice(span.Length);
        }

        public BigEndianAdvancingSpan TakeSlice(int length)
        {
            var returnValue = _internalSpan.Slice(0, length);
            _internalSpan = _internalSpan.Slice(length);
            return new BigEndianAdvancingSpan(returnValue);
        }

        public BigEndianAdvancingSpan ReadVector<[Primitive] T>() where T : struct
        {
            if(typeof(T) == typeof(byte))
            {
                var size = Read<byte>();
                return TakeSlice(size);
            }
            else if (typeof(T) == typeof(ushort) || typeof(T) == typeof(short))
            {
                var size = Read<ushort>();
                return TakeSlice(size);
            }
            else if (typeof(T) == typeof(int) || typeof(T) == typeof(uint))
            {
                var size = Read<int>();
                return TakeSlice(size);
            }
            Alerts.AlertException.ThrowDecode($"Error decoding a vector with type {typeof(T)}");
            return default(BigEndianAdvancingSpan);
        }
    }
}
