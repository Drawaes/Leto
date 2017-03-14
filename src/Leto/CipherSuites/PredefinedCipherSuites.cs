using Leto.Keyshares;
using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.CipherSuites
{
    public static class PredefinedCipherSuites
    {
        public static readonly CipherSuite RSA_AES_GCM_SHA256 = new CipherSuite(0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256", KeyExchangeType.Rsa, TlsVersion.Tls12);
        public static readonly CipherSuite RSA_AES_GCM_SHA384 = new CipherSuite(0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384", KeyExchangeType.Rsa, TlsVersion.Tls12);
    }
}
