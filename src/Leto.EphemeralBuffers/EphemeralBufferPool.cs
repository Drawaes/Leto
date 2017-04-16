using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Leto.EphemeralBuffers
{
    public abstract class EphemeralBufferPool : BufferPool
    {
        private IntPtr _pointer;
        private readonly int _bufferCount;
        private readonly int _bufferSize;
        private ConcurrentQueue<EphemeralOwnedBuffer> _buffers = new ConcurrentQueue<EphemeralOwnedBuffer>();
        private readonly uint _totalAllocated;
        private int _currentAllocatedOffset;

        public EphemeralBufferPool(int bufferSize, int bufferCount)
        {
            if (bufferSize < 1) throw new ArgumentOutOfRangeException(nameof(bufferSize));
            if (bufferCount < 1) throw new ArgumentOutOfRangeException(nameof(bufferCount));

            var minimumMemoryRequired = bufferCount * bufferSize;
            var pageSize = GetPageSize();
            var pages = minimumMemoryRequired / pageSize + Math.Min(1, minimumMemoryRequired % pageSize);
            var totalAllocated = pages * pageSize;
            _bufferCount = totalAllocated / bufferSize;
            _bufferSize = bufferSize;
            _totalAllocated = (uint)totalAllocated;

            _pointer = AllocateMemory(_totalAllocated);
        }

        internal IntPtr Pointer => _pointer;

        public static EphemeralBufferPool CreateBufferPool(int bufferSize, int bufferCount)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return new EphemeralBufferPoolUnix(bufferSize, bufferCount);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return new EphemeralBufferPoolWindows(bufferSize, bufferCount);
            }
            else
            {
                ExceptionHelper.ThrowException(new NotSupportedException("Unknown OS for ephemeral buffer pool"));
                return null;
            }
        }

        protected abstract int GetPageSize();
        protected abstract IntPtr AllocateMemory(uint amountToAllocate);
        protected abstract void FreeMemory(IntPtr pointer, uint amountToAllocate);

        public override OwnedBuffer<byte> Rent(int minimumBufferSize)
        {
            if (minimumBufferSize > _bufferSize)
            {
                ExceptionHelper.RequestedBufferTooLarge();
            }
            if (_buffers.TryDequeue(out EphemeralOwnedBuffer result))
            {
                result.Lease();
                return result;
            }
            lock (_buffers)
            {
                if (_currentAllocatedOffset >= (_totalAllocated - _bufferSize))
                {
                    ExceptionHelper.OutOfAvailableBuffers();
                }
                _currentAllocatedOffset += _bufferSize;
                var buffer = new EphemeralOwnedBuffer(_currentAllocatedOffset, _bufferSize, this);
                return buffer;
            }
        }

        internal void Return(EphemeralOwnedBuffer ephemeralBuffer) => _buffers.Enqueue(ephemeralBuffer);

        protected unsafe override void Dispose(bool disposing)
        {
            Unsafe.InitBlock((void*)_pointer, 0, _totalAllocated);
            FreeMemory(_pointer, _totalAllocated);
            GC.SuppressFinalize(this);
        }

        ~EphemeralBufferPool()
        {
            Dispose(false);
        }
    }
}
