using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct EVP_PKEY_CTX
        {
            private IntPtr _ptr;

            public void Free()
            {
                EVP_PKEY_CTX_free(_ptr);
                _ptr = IntPtr.Zero;
            }

            internal bool IsValid()
            {
                return _ptr.ToInt64() > 0;
            }
        }
    }
}
