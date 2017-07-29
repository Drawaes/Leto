using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using static LegacyOpenSsl.Interop.LibCrypto;

namespace LegacyOpenSsl.Interop
{
    public static partial class OpenSsl
    {
        [DllImport(Libraries.LibSsl, CallingConvention = CallingConvention.Cdecl)]
        public static extern void SSL_set0_wbio(SSL ssl, BIO wbio);
    }
}
