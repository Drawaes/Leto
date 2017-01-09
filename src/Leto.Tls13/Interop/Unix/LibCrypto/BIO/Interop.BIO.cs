using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct BIO
        {
            private IntPtr _ptr;

            public void Free()
            {
                BIO_free(_ptr);
                _ptr = IntPtr.Zero;
            }
        }
    }
}
