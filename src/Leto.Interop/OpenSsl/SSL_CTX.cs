using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    public partial class OpenSsl
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct SSL_CTX
        {
            private IntPtr _ptr;

            public bool IsValid => _ptr != IntPtr.Zero;
        }
    }
}
