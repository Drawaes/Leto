using System;
using System.Runtime.InteropServices;

namespace Leto.Interop
{
    public static partial class LibCrypto
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct EVP_CIPHER_CTX
        {
            private IntPtr _ptr;

            public bool IsValid => _ptr != IntPtr.Zero;

            public void Free()
            {
                if (_ptr == IntPtr.Zero) return;
                EVP_CIPHER_CTX_free(_ptr);
                _ptr = IntPtr.Zero;
            }
        }
    }
}
