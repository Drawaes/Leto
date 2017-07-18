using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static Leto.Interop.LibCrypto;

namespace Leto.Interop
{
    public partial class OpenSsl
    {
        [DllImport(Libraries.LibSsl, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_set_accept_state(SSL ssl);
    }
}
