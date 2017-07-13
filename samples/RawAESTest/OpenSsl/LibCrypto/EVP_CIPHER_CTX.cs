using System;
using System.Runtime.InteropServices;

namespace Leto.OpenSsl11.Interop
{
    internal static partial class LibCrypto
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct EVP_CIPHER_CTX
        {
            private IntPtr _ptr;
            
            public void Free()
            {
                if (_ptr == IntPtr.Zero) return;
                EVP_CIPHER_CTX_free(_ptr);
                _ptr = IntPtr.Zero;
            }
        }
    }
}
