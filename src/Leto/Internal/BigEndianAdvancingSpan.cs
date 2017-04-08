using System;
using System.Binary;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;

namespace Leto.Internal
{
    public struct BigEndianAdvancingSpan
    {
        private Span<byte> _internalSpan;

        private static readonly bool _needsToBeReversed = BitConverter.IsLittleEndian;
        
        public T Read<T>() where T : struct
        {
            var size = Unsafe.SizeOf<T>();
            var returnValue = _internalSpan.Read<T>();
            _internalSpan = _internalSpan.Slice(size);
            if (_needsToBeReversed) returnValue = BufferExtensions.Reverse(returnValue);
            return returnValue;
        }

        public void Write<T>(T value) where T :struct
        {
            var size = Unsafe.SizeOf<T>();
            if (_needsToBeReversed) value = BufferExtensions.Reverse(value);
            _internalSpan.Write(value);
            _internalSpan = _internalSpan.Slice(size);
        }
                 
    }
}
