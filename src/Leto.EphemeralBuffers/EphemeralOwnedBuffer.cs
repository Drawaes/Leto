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

        public EphemeralOwnedBuffer(int offset, int length, EphemeralBufferPool pool)
            : base(null, 0, length, IntPtr.Add(pool.Pointer, offset))
        {
            _pool = pool;
            _offset = offset;
            _length = length;
        }

        private IntPtr PoolPointer => IntPtr.Add(_pool.Pointer, _offset);

        internal void Lease()
        {
            if (IsDisposed)
            {
                Initialize(null, 0, _length, PoolPointer);
            }
        }

        protected unsafe override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            //Run the dispose logic before we return to the pool to stop a race
            if (System.Threading.Volatile.Read(ref _pool._isDisposed) == 0)
            {
                Unsafe.InitBlock((void*)PoolPointer, 0, (uint)Length);
                _pool.Return(this);
            }
        }
    }
}