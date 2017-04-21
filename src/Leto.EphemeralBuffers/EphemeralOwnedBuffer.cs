using System;
using System.Buffers;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;

namespace Leto.EphemeralBuffers
{
    public class EphemeralOwnedBuffer : OwnedBuffer<byte>
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

        public unsafe override Span<byte> Span => new Span<byte>((void*)PoolPointer, _length);

        internal void Lease()
        {
            _disposed = false;
        }

        protected unsafe override void Dispose(bool disposing)
        {
            _disposed = true;
            base.Dispose(disposing);
            //Run the dispose logic before we return to the pool to stop a race
            if (System.Threading.Volatile.Read(ref _pool._isDisposed) == 0)
            {
                Unsafe.InitBlock((void*)(_pool.Pointer + _offset), 0, (uint)Length);
                _pool.Return(this);
            }
        }

        protected override bool TryGetArrayInternal(out ArraySegment<byte> buffer)
        {
            buffer = default(ArraySegment<byte>);
            return false;
        }

        protected override unsafe bool TryGetPointerInternal(out void* pointer)
        {
            pointer = (void*)(_pool.Pointer + _offset);
            return true;
        }
    }
}