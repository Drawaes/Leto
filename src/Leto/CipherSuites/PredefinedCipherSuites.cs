using Leto.Certificates;
using Leto.Keyshares;
using System;
using System.Collections.Generic;
using Leto.Hashes;

namespace Leto.CipherSuites
{
    public static class PredefinedCipherSuites
    {
        public static readonly CipherSuite RSA_AES_128_GCM_SHA256 = new CipherSuite(0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256", BulkCipherType.AES_128_GCM, HashType.SHA256, KeyExchangeType.Rsa, CertificateType.rsa, TlsVersion.Tls12);
        public static readonly CipherSuite RSA_AES_256_GCM_SHA384 = new CipherSuite(0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384", BulkCipherType.AES_256_GCM, HashType.SHA384, KeyExchangeType.Rsa, CertificateType.rsa, TlsVersion.Tls12);
    }
}
