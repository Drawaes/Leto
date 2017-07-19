using System;
using System.Collections.Generic;
using System.Text;

namespace SslStream3.Internal
{
    public class SslBuffer :IDisposable
    {
        private static int _bufferSize = 16 * 1024;
        private static PinnableBufferCache _cache = new PinnableBufferCache("Leto.SslStream", Create);

        private byte[] _buffer = new byte[_bufferSize];
        private int _bytesAvailable = 0;
        private int _byteOffset = 0;

        public SslBuffer()
        {
        }

        public int StartOfEmptySpace => _byteOffset + _bytesAvailable;
        public int FreeSpace => _buffer.Length - StartOfEmptySpace;
        public int StartOfBytes => _byteOffset;
        public int BytesAvailable => _bytesAvailable;
        public byte[] Array => _buffer;

        public void AddedBytes(int byteCount) => _bytesAvailable += byteCount;

        public ReadOnlySpan<byte> GetReadSpan(int numberOfBytes)
        {
            var actualBytes = Math.Min(numberOfBytes, _bytesAvailable);
            if (actualBytes == 0) return default(ReadOnlySpan<byte>);
            var returnSpan = new ReadOnlySpan<byte>(_buffer, _byteOffset, actualBytes);
            _bytesAvailable -= actualBytes;
            if (_bytesAvailable == 0)
            {
                _byteOffset = 0;
            }
            else
            {
                _byteOffset += actualBytes;
            }
            return returnSpan;
        }

        public Span<byte> GetWriteSpan(int numberOfBytes)
        {
            var actualBytes = Math.Min(numberOfBytes, FreeSpace);
            var returnSpan = new Span<byte>(_buffer, StartOfEmptySpace, actualBytes);
            _bytesAvailable += actualBytes;
            return returnSpan;
        }

        public void MoveDataToFront()
        {
            if (_byteOffset == 0) throw new InvalidOperationException("All the bytes are already at the front of the array");

            var newArray = GetBuffer();
            Buffer.BlockCopy(_buffer, _byteOffset, newArray._buffer, 0, _bytesAvailable);
            _byteOffset = 0;
            var oldBuffer = _buffer;
            _buffer = newArray._buffer;
            newArray._buffer = oldBuffer;
            newArray.Dispose();
        }

        private static SslBuffer Create() => new SslBuffer();

        public static SslBuffer GetBuffer() => (SslBuffer)_cache.Allocate();

        public void Dispose()
        {
            _byteOffset = 0;
            _bytesAvailable = 0;
            _cache.Free(this);
        }

        internal void Clear()
        {
            _byteOffset = 0;
            _bytesAvailable = 0;
        }
    }
}
