using System;
using System.Runtime.InteropServices;

namespace Leto.Interop
{
    public static partial class LibCrypto
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct BIGNUM
        {
            private IntPtr _ptr;

            public bool IsValid => _ptr != IntPtr.Zero;

            public void Free()
            {
                if (!IsValid) return;
                BN_clear_free(_ptr);
                _ptr = IntPtr.Zero;
            }
        }
    }
}
