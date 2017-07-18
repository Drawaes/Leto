using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    public partial class OpenSsl
    {
        public struct SSL_CTX
        {
            private IntPtr _pointer;
        }
    }
}
