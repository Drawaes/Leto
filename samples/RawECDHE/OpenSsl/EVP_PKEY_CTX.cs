using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.OpenSsl11.Interop
{
    internal partial class LibCrypto
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct EVP_PKEY_CTX
        {
            private IntPtr _ptr;

            public void Free()
            {
                if (_ptr == IntPtr.Zero) return;
                EVP_PKEY_CTX_free(_ptr);
                _ptr = IntPtr.Zero;
            }
        }
    }
}
