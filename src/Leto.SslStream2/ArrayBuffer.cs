using System;
using System.Buffers;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace Leto.SslStream2
{
    public class ArrayBuffer:IDisposable
    {
        private static readonly int _bufferSize = 16 * 1024;
        private static readonly ArrayPool<byte> _pool = ArrayPool<byte>.Create(_bufferSize, 1000);
        private static int _bufferRented = 0;

        private byte[] _internalArray;
        private int _bytesAvailable = 0;
        private int _byteOffset = 0;
        private GCHandle _pinned;

        public ArrayBuffer()
        {
            Interlocked.Increment(ref _bufferRented);
            Console.WriteLine($"Buffers Rented {_bufferRented}");
            _internalArray = _pool.Rent(_bufferSize);
            _pinned = GCHandle.Alloc(_internalArray, GCHandleType.Pinned);
        }

        public int StartOfEmptySpace => _byteOffset + _bytesAvailable;
        public int FreeSpace => _internalArray.Length - StartOfEmptySpace;
        public int StartOfBytes => _byteOffset;
        public int BytesAvailable => _bytesAvailable;
        public byte[] Array => _internalArray;

        public void Dispose()
        {
            if(_internalArray != null)
            {
                _pinned.Free();
                _pool.Return(_internalArray, true);
                Interlocked.Decrement(ref _bufferRented);
                Console.WriteLine($"Buffers Rented {_bufferRented}");
                _internalArray = null;
                
            }
        }

        public void AddedBytes(int byteCount) => _bytesAvailable += byteCount;

        public ReadOnlySpan<byte> GetReadSpan(int numberOfBytes)
        {
            var actualBytes = Math.Min(numberOfBytes, _bytesAvailable);
            if (actualBytes == 0) return default(ReadOnlySpan<byte>);
            var returnSpan = new ReadOnlySpan<byte>(_internalArray, _byteOffset, actualBytes);
            _bytesAvailable -= actualBytes;
            if(_bytesAvailable == 0)
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
            var returnSpan = new Span<byte>(_internalArray, StartOfEmptySpace, actualBytes);
            _bytesAvailable += actualBytes;
            return returnSpan;
        }

        public void Clear()
        {
            _byteOffset = 0;
            _bytesAvailable = 0;
        }

        internal void MoveDataToFront()
        {
            if (_byteOffset == 0) throw new InvalidOperationException("All the bytes are already at the front of the array");

            var newArray = _pool.Rent(_bufferSize);
            Buffer.BlockCopy(_internalArray, _byteOffset, newArray, 0, _bytesAvailable);
            _pinned.Free();
            _pool.Return(_internalArray);
            _internalArray = newArray;
            _pinned = GCHandle.Alloc(_internalArray, GCHandleType.Pinned);
            _byteOffset = 0;
        }
    }
}
