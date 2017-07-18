using System;
using System.Runtime.InteropServices;

namespace Leto.Interop
{
    public static partial class LibCrypto
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct EC_POINT
        {
            private IntPtr _ptr;

            public bool IsValid => _ptr != IntPtr.Zero;

            public void Free()
            {
                if (_ptr == IntPtr.Zero) return;
                EC_POINT_free(_ptr);
                _ptr = IntPtr.Zero;
            }
        }

        public enum EC_POINT_CONVERSION : int
        {
            POINT_CONVERSION_UNCOMPRESSED = 4,
            POINT_CONVERSION_COMPRESSED = 2,
        }
    }
}
