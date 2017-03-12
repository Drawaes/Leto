using System;
using System.Buffers;
using System.Buffers.Pools;
using System.Collections.Concurrent;
using System.Diagnostics;
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
                var mem = new EphemeralMemory(IntPtr.Add(_memory, i), bufferSize);
                _buffers.Enqueue(mem);
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
                ExceptionHelper.ThrowException(new OutOfMemoryException());
            }
            returnValue.Rented = true;
            return returnValue;
        }

        public override void Return(OwnedMemory<byte> buffer)
        {
            var ephemeralBuffer = buffer as EphemeralMemory;
            if (ephemeralBuffer == null)
            {
                Debug.Fail("The buffer was not ephemeral");
                return;
            }
            Debug.Assert(ephemeralBuffer.Rented, "Returning a buffer that isn't rented!");
            if (!ephemeralBuffer.Rented)
            {
                return;
            }
            ephemeralBuffer.Rented = false;
            RtlZeroMemory(ephemeralBuffer.Pointer, (UIntPtr)ephemeralBuffer.Length);
            _buffers.Enqueue(ephemeralBuffer);
        }

        sealed class EphemeralMemory : OwnedMemory<byte>
        {
            public EphemeralMemory(IntPtr memory, int length) : base(null, 0, length, memory)
            {
            }
            internal bool Rented;
            public new IntPtr Pointer => base.Pointer;
        }

        protected override void Dispose(bool disposing)
        {
            RtlZeroMemory(_memory, _totalAllocated);
            VirtualFree(_memory, _totalAllocated, 0x8000);
            GC.SuppressFinalize(this);
        }

        ~EphemeralBufferPoolWindows()
        {
            Dispose();
        }
    }
}
