using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static Leto.Interop.LibCrypto;

namespace Leto.Interop
{
    public static partial class OpenSsl
    {
        [DllImport(Libraries.LibSsl, CallingConvention = CallingConvention.Cdecl, EntryPoint = nameof(SSL_CTX_use_certificate))]
        private unsafe extern static int Internal_SSL_CTX_use_certificate(SSL_CTX ctx, X509 cert);

        public static void SSL_CTX_use_certificate(SSL_CTX ctx, X509 cert)
        {
            var result = Internal_SSL_CTX_use_certificate(ctx, cert);
            ThrowOnErrorReturnCode(result);
        }
    }
}
