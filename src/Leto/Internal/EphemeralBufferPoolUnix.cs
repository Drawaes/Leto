using System;
using System.Buffers;
using System.Buffers.Pools;
using System.Collections.Concurrent;
using System.Diagnostics;
using static Leto.Interop.Sys;

namespace Leto.Internal
{
    public sealed class EphemeralBufferPoolUnix : BufferPool
    {
        private readonly IntPtr _memory;
        private readonly int _bufferCount;
        private readonly int _bufferSize;
        private readonly ConcurrentQueue<EphemeralMemory> _buffers = new ConcurrentQueue<EphemeralMemory>();
        private readonly long _totalAllocated;

        public EphemeralBufferPoolUnix(int bufferSize, int bufferCount)
        {
            if (bufferSize < 1)
            {
                ExceptionHelper.ThrowException(new ArgumentOutOfRangeException(nameof(bufferSize)));
            }
            if (bufferCount < 1)
            {
                ExceptionHelper.ThrowException(new ArgumentOutOfRangeException(nameof(bufferSize)));
            }

            var pageSize = SysConf(SysConfName._SC_PAGESIZE);
            if (pageSize < 0)
            {
                ExceptionHelper.MemeoryBadPageSize();
            }

            var pages = (int)Math.Ceiling((bufferCount * bufferSize) / (double)pageSize);
            _totalAllocated = pages * pageSize;
            _bufferCount = (int)_totalAllocated / bufferSize;
            _bufferSize = bufferSize;
            _memory = MMap(IntPtr.Zero, (ulong)_totalAllocated, MemoryMappedProtections.PROT_READ | MemoryMappedProtections.PROT_WRITE, MemoryMappedFlags.MAP_PRIVATE | MemoryMappedFlags.MAP_ANONYMOUS, new IntPtr(-1), 0);
            if (_memory.ToInt64() < 0)
            {
                ExceptionHelper.MemeoryBadPageSize();
            }
            if (MLock(_memory, (ulong)_totalAllocated) < 0)
            {
                ExceptionHelper.MemeoryBadPageSize();
            }

            for (var i = 0; i < _totalAllocated; i += bufferSize)
            {
                var mem = new EphemeralMemory(IntPtr.Add(_memory, i), bufferSize, this);
                _buffers.Enqueue(mem);
            }
        }

        private sealed class EphemeralMemory : OwnedMemory<byte>
        {
            private EphemeralBufferPoolUnix _pool;
            public EphemeralMemory(IntPtr memory, int length, EphemeralBufferPoolUnix pool) : base(null, 0, length, memory)
            {
                _pool = pool;
            }
            internal bool Rented;
            protected override void Dispose(bool disposing)
            {
                MemSet(Pointer, 0, (UIntPtr)Length);
                _pool.Return(this);
            }
        }

        public override OwnedMemory<byte> Rent(int minimumBufferSize)
        {
            if (minimumBufferSize > _bufferSize)
            {
                ExceptionHelper.ThrowException(new OutOfMemoryException("Buffer requested was larger than the max size"));
            }
            if (!_buffers.TryDequeue(out EphemeralMemory returnValue))
            {
                ExceptionHelper.ThrowException(new OutOfMemoryException("Ran out of free buffers"));
            }
            returnValue.Rented = true;
            return returnValue;
        }

        private void Return(OwnedMemory<byte> buffer)
        {
            var emphemeralBuffer = buffer as EphemeralMemory;
            if (emphemeralBuffer == null)
            {
                ExceptionHelper.MemoryBufferNotEphemeral();
            }
            if (!emphemeralBuffer.Rented)
            {
                Debug.Fail("Returning a buffer that isn't rented!");
                return;
            }
            emphemeralBuffer.Rented = false;
            _buffers.Enqueue(emphemeralBuffer);
        }

        protected override void Dispose(bool disposing)
        {
            MemSet(_memory, 0, (UIntPtr)_totalAllocated);
            if (MUnmap(_memory, (ulong)_totalAllocated) < 0)
            {
                ///aggggggggg
                Debug.Fail("Didn't let go of the memory");
            }
            GC.SuppressFinalize(this);
        }

        ~EphemeralBufferPoolUnix()
        {
            Dispose();
        }
    }
}
