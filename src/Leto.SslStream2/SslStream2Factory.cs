using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using static Leto.Interop.LibCrypto;
using static Leto.Interop.OpenSsl;

namespace Leto.SslStream2
{
    public class SslStream2Factory
    {
        private SSL_CTX _ctx;

        public SslStream2Factory(string pfxFile, string password)
        {
            var bytes = File.ReadAllBytes(pfxFile);
            var p12 = d2i_PKCS12(bytes);
            var (key, cert) = PKCS12_parse(p12, "test");
            p12.Free();

            _ctx = SSL_CTX_new(TLS_server_method());
            SSL_CTX_use_PrivateKey(_ctx, key);
            SSL_CTX_use_certificate(_ctx, cert);
        }

        public SslStreamPOC GetStream(Stream innerStream)
        {
            var stream = new SslStreamPOC(innerStream, _ctx);
            return stream;
        }
    }
}
