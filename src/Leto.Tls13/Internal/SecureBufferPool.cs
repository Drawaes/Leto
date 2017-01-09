using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static Interop.Kernel32;

namespace Leto.Tls13.Internal
{
    public class SecureBufferPool
    {
        private IntPtr _memory;
        private int _bufferCount;
        private int _bufferSize;
        private ConcurrentQueue<OwnedMemory<byte>> _buffers = new ConcurrentQueue<OwnedMemory<byte>>();
        private UIntPtr _totalAllocated;
        private byte[] _emptyData;

        public SecureBufferPool(int bufferSize, int bufferCount)
        {
            if (bufferSize < 1) throw new ArgumentOutOfRangeException(nameof(bufferSize));
            if (bufferCount < 1) throw new ArgumentOutOfRangeException(nameof(bufferSize));

            _emptyData = new byte[bufferSize];
            SYSTEM_INFO sysInfo;
            GetSystemInfo(out sysInfo);
            var pages = (int)Math.Ceiling((bufferCount * bufferSize) / (double)sysInfo.dwPageSize);
            var totalAllocated = pages * sysInfo.dwPageSize;
            _bufferCount = totalAllocated / bufferSize;
            _bufferSize = bufferSize;
            _totalAllocated = new UIntPtr((uint)totalAllocated);

            _memory = VirtualAlloc(IntPtr.Zero, _totalAllocated, MemOptions.MEM_COMMIT | MemOptions.MEM_RESERVE, PageOptions.PAGE_READWRITE);
            VirtualLock(_memory, _totalAllocated);
            for(var i = 0; i < totalAllocated; i += bufferSize)
            {
                var mem = new SecureMemory(IntPtr.Add(_memory, i), bufferSize);
                _buffers.Enqueue(mem);
            }
        }

        public OwnedMemory<byte> Rent()
        {
            OwnedMemory<byte> returnValue;
            if(!_buffers.TryDequeue(out returnValue))
            {
                ExceptionHelper.ThrowException(new OutOfMemoryException());
            }
            return returnValue;
        }

        internal void Dispose()
        {
            throw new NotImplementedException();
        }

        public void Return(OwnedMemory<byte> buffer)
        {
            _emptyData.CopyTo(buffer.Span);
            _buffers.Enqueue(buffer);
        }

        sealed class SecureMemory : OwnedMemory<byte>
        {
            public SecureMemory(IntPtr memory, int length) : base(null, 0, length, memory)
            { }

            public new IntPtr Pointer => base.Pointer;
        }
    }
}
