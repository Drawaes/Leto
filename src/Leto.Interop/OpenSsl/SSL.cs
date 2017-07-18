using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    public partial class OpenSsl
    {
        public struct SSL
        {
            private IntPtr _ptr;

            public bool IsValid => _ptr != IntPtr.Zero;


            public void Free()
            {
                if (!IsValid) return;
                SSL_free(this);
                _ptr = IntPtr.Zero;
            }
        }
    }
}
