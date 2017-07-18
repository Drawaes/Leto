using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using static Leto.Interop.LibCrypto;

namespace Leto.Interop
{
    public partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal extern static void PKCS12_free(PKCS12 p12);
    }
}
