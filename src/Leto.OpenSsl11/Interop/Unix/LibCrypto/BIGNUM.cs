using System;
using System.Runtime.InteropServices;

namespace Leto.OpenSsl11.Interop
{
    internal partial class LibCrypto
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct BIGNUM
        {
            private IntPtr _ptr;

            public bool IsAllocated => _ptr != IntPtr.Zero;

            public void Free()
            {
                if (!IsAllocated) return;
                BN_clear_free(_ptr);
                _ptr = IntPtr.Zero;
            }
        }
    }
}
