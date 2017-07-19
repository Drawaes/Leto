using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using static Leto.Interop.LibCrypto;
using static Leto.Interop.OpenSsl;

namespace SslStream3
{
    public class SslStream3Factory : IDisposable
    {
        private SSL_CTX _ctx;
        private EVP_PKEY _key;
        private X509 _cert;
        private PKCS12 _pkcs12;

        public SslStream3Factory(string pfxFile, string password)
        {
            var bytes = File.ReadAllBytes(pfxFile);
            _pkcs12 = d2i_PKCS12(bytes);
            (_key, _cert) = PKCS12_parse(_pkcs12, "test");

            _ctx = SSL_CTX_new(TLS_server_method());
            SSL_CTX_use_PrivateKey(_ctx, _key);
            SSL_CTX_use_certificate(_ctx, _cert);
            SSL_CTX_set_max_proto_version(_ctx, TLS_VERSION.TLS1_2_VERSION);
        }

        public void Dispose()
        {
            _ctx.Dispose();
            _pkcs12.Dispose();
        }

        public SslStreamPOC GetStream(Stream innerStream) => new SslStreamPOC(innerStream, _ctx);
    }
}
