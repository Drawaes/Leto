using System;
using System.Runtime.InteropServices;

namespace Leto.OpenSsl11.Interop
{
    internal static partial class LibCrypto
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct EC_POINT
        {
            private IntPtr _ptr;

            public void Free()
            {
                if (_ptr == IntPtr.Zero) return;
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
