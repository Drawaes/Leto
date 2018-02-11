using System;
using System.Buffers;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;

namespace Leto.EphemeralBuffers
{
    public class EphemeralOwnedBuffer : OwnedMemory<byte>
    {
        private EphemeralBufferPool _pool;
        private int _offset;
        private int _length;
        private bool _disposed = false;

        public EphemeralOwnedBuffer(int offset, int length, EphemeralBufferPool pool)
        {
            _pool = pool;
            _offset = offset;
            _length = length;
        }

        private IntPtr PoolPointer
        {
            get
            {
                if (_disposed)
                {
                    throw new ObjectDisposedException(nameof(EphemeralOwnedBuffer));
                }
                return _pool.Pointer + _offset;
            }
        }

        public override int Length => _length;

        public override bool IsDisposed => _disposed;

        protected override bool IsRetained => false;

        internal void Lease() => _disposed = false;

        protected unsafe override void Dispose(bool disposing)
        {
            _disposed = true;
            if (System.Threading.Volatile.Read(ref _pool._isDisposed) == 0)
            {
                Unsafe.InitBlock((void*)(_pool.Pointer + _offset), 0, (uint)Length);
                _pool.Return(this);
            }
        }

        public unsafe override Span<byte> Span => new Span<byte>((void*)(_pool.Pointer + _offset), _length);

        public override BufferHandle Pin(int index = 0)
        {
            throw new NotImplementedException();
        }

        protected override bool TryGetArray(out ArraySegment<byte> buffer)
        {
            buffer = default(ArraySegment<byte>);
            return false;
        }

        public override void Retain()
        {
            throw new NotImplementedException();
        }

        public override bool Release()
        {
            throw new NotImplementedException();
        }
    }
}
