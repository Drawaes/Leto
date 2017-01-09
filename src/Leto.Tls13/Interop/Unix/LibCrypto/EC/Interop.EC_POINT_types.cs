using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct EC_POINT
        {
            private IntPtr _ptr;

            public void Free()
            {
                EC_POINT_free(_ptr);
                _ptr = IntPtr.Zero;
            }
        }

        internal enum EC_POINT_CONVERSION : int
        {
            POINT_CONVERSION_UNCOMPRESSED = 4,
            POINT_CONVERSION_COMPRESSED = 2,
        }
    }
}
