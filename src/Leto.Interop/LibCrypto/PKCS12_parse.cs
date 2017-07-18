using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using static Leto.Interop.LibCrypto;

namespace Leto.Interop
{
    public partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private extern static int PKCS12_parse(PKCS12 p12, string pass, out EVP_PKEY pkey,out X509 cert, IntPtr ca);

        public static (EVP_PKEY privateKey, X509 certificate) PKCS12_parse(PKCS12 p12, string password)
        {
            ThrowOnErrorReturnCode(PKCS12_parse(p12, password, out EVP_PKEY privateKey, out X509 cert, IntPtr.Zero));
            return (privateKey, cert);
        }
    }
}
