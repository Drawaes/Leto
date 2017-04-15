using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using static Leto.Interop.Kernel32;

namespace Leto.Internal
{
    public sealed class EphemeralBufferPoolWindows : BufferPool
    {
        private readonly IntPtr _memory;
        private readonly int _bufferCount;
        private readonly int _bufferSize;
        private readonly ConcurrentQueue<EphemeralMemory> _buffers = new ConcurrentQueue<EphemeralMemory>();
        private readonly UIntPtr _totalAllocated;
        private bool _disposed;
        
        public EphemeralBufferPoolWindows(int bufferSize, int bufferCount)
        {
            if (bufferSize < 1) throw new ArgumentOutOfRangeException(nameof(bufferSize));
            if (bufferCount < 1) throw new ArgumentOutOfRangeException(nameof(bufferSize));

            GetSystemInfo(out SYSTEM_INFO sysInfo);
            var pages = (int)Math.Ceiling((bufferCount * bufferSize) / (double)sysInfo.dwPageSize);
            var totalAllocated = pages * sysInfo.dwPageSize;
            _bufferCount = totalAllocated / bufferSize;
            _bufferSize = bufferSize;
            _totalAllocated = new UIntPtr((uint)totalAllocated);

            _memory = VirtualAlloc(IntPtr.Zero, _totalAllocated, MemOptions.MEM_COMMIT | MemOptions.MEM_RESERVE, PageOptions.PAGE_READWRITE);
            VirtualLock(_memory, _totalAllocated);
            for (var i = 0; i < totalAllocated; i += bufferSize)
            {
                var mem = new EphemeralMemory(IntPtr.Add(_memory, i), bufferSize, this);
                _buffers.Enqueue(mem);
            }
        }

        public override OwnedBuffer<byte> Rent(int minimumBufferSize)
        {
            if (minimumBufferSize > _bufferSize)
            {
                ExceptionHelper.ThrowException(new OutOfMemoryException("Buffer requested was larger than the max size"));
            }
            if (!_buffers.TryDequeue(out EphemeralMemory returnValue))
            {
                ExceptionHelper.ThrowException(new OutOfMemoryException());
            }
            returnValue.Rented = true;
            return returnValue;
        }

        private void Return(EphemeralMemory ephemeralBuffer)
        {
            if (!ephemeralBuffer.Rented)
            {
                Debug.Fail("Returning a buffer that isn't rented!");
                return;
            }
            ephemeralBuffer.Rented = false;
            _buffers.Enqueue(ephemeralBuffer);
        }

        sealed class EphemeralMemory : OwnedBuffer<byte>
        {
            private EphemeralBufferPoolWindows _pool;
            public EphemeralMemory(IntPtr memory, int length, EphemeralBufferPoolWindows pool)
                : base(null, 0, length, memory) => _pool = pool;

            internal bool Rented;
            protected unsafe override void Dispose(bool disposing)
            {
                if(! System.Threading.Volatile.Read(ref _pool._disposed))
                {
                    Unsafe.InitBlock((void*)Pointer, 0, (uint)Length);
                }
                _pool.Return(this);
                base.Dispose(disposing);
            }
        }

        protected unsafe override void Dispose(bool disposing)
        {
            if(System.Threading.Volatile.Read(ref _disposed))
            {
                return;
            }
            System.Threading.Volatile.Write(ref _disposed, true);
            Unsafe.InitBlock((void*)_memory, 0, (uint)_totalAllocated);
            VirtualFree(_memory, _totalAllocated, 0x8000);
            GC.SuppressFinalize(this);
        }

        ~EphemeralBufferPoolWindows()
        {
            Dispose();
        }
    }
}
