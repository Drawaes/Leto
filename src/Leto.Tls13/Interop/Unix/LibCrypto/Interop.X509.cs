using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct X509
        {
            public IntPtr Ptr;

            public void Free()
            {
                X509_free(Ptr);
                Ptr = IntPtr.Zero;
            }
        }
    }
}
