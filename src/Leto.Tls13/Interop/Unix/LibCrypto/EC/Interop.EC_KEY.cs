using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct EC_KEY
        {
            public IntPtr Ptr;

            public void Free()
            {
                EC_KEY_free(Ptr);
                Ptr = IntPtr.Zero;
            }
        }
    }
}
