using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static LegacyOpenSsl.Interop.LibCrypto;

namespace LegacyOpenSsl.Interop
{
    public static partial class OpenSsl
    {
        [DllImport(Libraries.LibSsl, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_set_accept_state(SSL ssl);
    }
}
