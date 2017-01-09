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
            private IntPtr _ptr;

            public void Free()
            {
                EC_KEY_free(_ptr);
                _ptr = IntPtr.Zero;
            }
        }
    }
}
