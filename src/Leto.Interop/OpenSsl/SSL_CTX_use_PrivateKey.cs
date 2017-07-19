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
        [DllImport(Libraries.LibSsl, CallingConvention = CallingConvention.Cdecl, EntryPoint =nameof(SSL_CTX_use_PrivateKey))]
        private unsafe extern static int Internal_SSL_CTX_use_PrivateKey(SSL_CTX ctx, EVP_PKEY pkey);

        public static void SSL_CTX_use_PrivateKey(SSL_CTX ctx, EVP_PKEY key)
        {
            var result = Internal_SSL_CTX_use_PrivateKey(ctx, key);
            ThrowOnErrorReturnCode(result);
        }
    }
}
