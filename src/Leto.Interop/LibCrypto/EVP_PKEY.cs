using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    public partial class LibCrypto
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct EVP_PKEY
        {
            private IntPtr _ptr;

            public bool IsValid => _ptr != IntPtr.Zero;

            public void Free()
            {
                if (IsValid) return;
                EVP_PKEY_free(_ptr);
                _ptr = IntPtr.Zero;
            }
        }
    }
}
