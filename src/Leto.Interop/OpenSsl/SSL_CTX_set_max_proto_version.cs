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
        public unsafe static void SSL_CTX_set_max_proto_version(SSL_CTX ctx, TLS_VERSION version)
        {
            var result = SSL_CTX_ctrl(ctx, SSL_CTRL.SSL_CTRL_SET_MAX_PROTO_VERSION, (int)version, null);
            ThrowOnErrorReturnCode(result);
        }
    }
}
