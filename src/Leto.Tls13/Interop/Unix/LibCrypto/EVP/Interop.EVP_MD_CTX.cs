using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct EVP_MD_CTX
        {
            private IntPtr _ptr;

            public void Free()
            {
                EVP_MD_CTX_free(_ptr);
                _ptr = IntPtr.Zero;
            }
        }
    }
}
