using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct BIGNUM
        {
            private IntPtr _ptr;

            public void Free()
            {
                BN_clear_free(_ptr);
                _ptr = IntPtr.Zero;
            }
        }
    }
}
