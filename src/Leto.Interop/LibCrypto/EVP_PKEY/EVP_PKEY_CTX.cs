using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    public static partial class LibCrypto
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct EVP_PKEY_CTX
        {
            private IntPtr _ptr;

            public bool IsValid => _ptr != IntPtr.Zero;

            public void Free()
            {
                if (!IsValid) return;
                EVP_PKEY_CTX_free(_ptr);
                _ptr = IntPtr.Zero;
            }
        }
    }
}
