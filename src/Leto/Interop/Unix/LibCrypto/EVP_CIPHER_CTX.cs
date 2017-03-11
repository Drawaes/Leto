using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    internal static partial class LibCrypto
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct EVP_CIPHER_CTX
        {
            private IntPtr _ptr;

            public bool IsValid() => _ptr != IntPtr.Zero;

            public void Free()
            {
                EVP_CIPHER_CTX_free(_ptr);
                _ptr = IntPtr.Zero;
            }
        }
    }
}
