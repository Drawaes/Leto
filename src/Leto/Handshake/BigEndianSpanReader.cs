using System;
using System.Collections.Generic;
using System.Runtime;
using System.Runtime.CompilerServices;
using System.Text;

namespace Leto.Handshake
{
    public struct BigEndianSpanReader
    {
        private Span<byte> _span;

        public BigEndianSpanReader(Span<byte> span)
        {
            _span = span;
        }

        public int Length => _span.Length;

        public Span<byte> ReadVector16()
        {
            var size = Read<ushort>();
            var newSpan = _span.Slice(0, size);
            _span = _span.Slice(size);
            return newSpan;
        }

        public Span<byte> ReadVector8()
        {
            var size = Read<byte>();
            var newSpan = _span.Slice(0, size);
            _span = _span.Slice(size);
            return newSpan;
        }

        public Span<byte> ReadFixed(int size)
        {
            var newSpan = _span.Slice(0, size);
            _span = _span.Slice(size);
            return newSpan;
        }

        public T Read<T>() where T : struct
        {
            var returnValue = UnsafeUtilities.Reverse(_span.Read<T>());
            _span = _span.Slice(Unsafe.SizeOf<T>());
            return returnValue;
        }
    }
}
