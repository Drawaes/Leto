using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using static Interop.Sys;

namespace Leto.Tls13.Internal
{
    public class EphemeralBufferPoolUnix: BufferPool
    {
        private IntPtr _memory;
        private int _bufferCount;
        private int _bufferSize;
        private ConcurrentQueue<EphemeralMemory> _buffers = new ConcurrentQueue<EphemeralMemory>();
        private long _totalAllocated;
        
        public EphemeralBufferPoolUnix(int bufferSize, int bufferCount)
        {
            if (bufferSize < 1) throw new ArgumentOutOfRangeException(nameof(bufferSize));
            if (bufferCount < 1) throw new ArgumentOutOfRangeException(nameof(bufferSize));

            var pageSize = SysConf(SysConfName._SC_PAGESIZE);
            if(pageSize < 0)
            {
                ExceptionHelper.ThrowException(new InvalidOperationException("Unable to get system page size"));
            }
            var pages = (int)Math.Ceiling((bufferCount * bufferSize) / (double)pageSize);
            _totalAllocated = pages * pageSize;
            _bufferCount = (int)_totalAllocated / bufferSize;
            _bufferSize = bufferSize;
            _memory = MMap(IntPtr.Zero, (ulong)_totalAllocated, MemoryMappedProtections.PROT_READ | MemoryMappedProtections.PROT_WRITE, MemoryMappedFlags.MAP_PRIVATE | MemoryMappedFlags.MAP_ANONYMOUS, new IntPtr(-1), 0);
            if(_memory.ToInt64() < 0)
            {
                ExceptionHelper.ThrowException(new InvalidOperationException("Unable to get system page size"));
            }
            if(MLock(_memory, (ulong)_totalAllocated) < 0)
            {
                ExceptionHelper.ThrowException(new InvalidOperationException("Unable to get system page size"));
            }
            
            for (var i = 0; i < _totalAllocated; i += bufferSize)
            {
                var mem = new EphemeralMemory(IntPtr.Add(_memory, i), bufferSize);
                _buffers.Enqueue(mem);
            }
        }

        private sealed class EphemeralMemory : OwnedMemory<byte>
        {
            public EphemeralMemory(IntPtr memory, int length) : base(null, 0, length, memory)
            { }
            internal bool Rented;
            public new IntPtr Pointer => base.Pointer;
        }

        public override OwnedMemory<byte> Rent(int minimumBufferSize)
        {
            if (minimumBufferSize > _bufferSize)
            {
                ExceptionHelper.ThrowException(new OutOfMemoryException("Buffer requested was larger than the max size"));
            }
            EphemeralMemory returnValue;
            if (!_buffers.TryDequeue(out returnValue))
            {
                ExceptionHelper.ThrowException(new OutOfMemoryException());
            }
            returnValue.Rented = true;
            return returnValue;
        }

        public override unsafe void Return(OwnedMemory<byte> buffer)
        {
            var buffer2 = buffer as EphemeralMemory;
            if (buffer2 == null)
            {
                Debug.Fail("The buffer was not Ephemeral");
                return;
            }
            Debug.Assert(buffer2.Rented, "Returning a buffer that isn't rented!");
            if (!buffer2.Rented)
            {
                return;
            }
            buffer2.Rented = false;
            MemSet((void*)buffer2.Pointer, 0, (UIntPtr)buffer2.Length);
            _buffers.Enqueue(buffer2);
        }

        protected unsafe override void Dispose(bool disposing)
        {
            MemSet((void*)_memory, 0, (UIntPtr)_totalAllocated);
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
