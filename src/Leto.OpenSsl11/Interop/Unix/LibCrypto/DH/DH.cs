using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.OpenSsl11.Interop
{
    internal static partial class LibCrypto
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct DH
        {
            private IntPtr _ptr;

            public bool IsAllocated => _ptr != IntPtr.Zero;

            public void Free()
            {
                if (!IsAllocated) return;
                DH_free(_ptr);
                _ptr = IntPtr.Zero;
            }
        }
    }
}
