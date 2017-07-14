using System;
using System.Runtime.InteropServices;

namespace Leto.OpenSsl11.Interop
{
    internal static partial class LibCrypto
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct EC_KEY
        {
            private IntPtr _ptr;

            public void Free()
            {
                if (_ptr == IntPtr.Zero) return;
                EC_KEY_free(_ptr);
                _ptr = IntPtr.Zero;
            }
        }
    }
}
