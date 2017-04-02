using Leto.Certificates;
using Leto.KeyExchanges;
using System;
using System.Collections.Generic;
using Leto.Hashes;

namespace Leto.CipherSuites
{
    public static class PredefinedCipherSuites
    {
        public static readonly CipherSuite RSA_AES_128_GCM_SHA256 = new CipherSuite(0x009C, nameof(RSA_AES_128_GCM_SHA256), BulkCipherType.AES_128_GCM, HashType.SHA256, KeyExchangeType.Rsa, CertificateType.rsa, TlsVersion.Tls12);
        public static readonly CipherSuite RSA_AES_256_GCM_SHA384 = new CipherSuite(0x009D, nameof(RSA_AES_256_GCM_SHA384), BulkCipherType.AES_256_GCM, HashType.SHA384, KeyExchangeType.Rsa, CertificateType.rsa, TlsVersion.Tls12);
        public static readonly CipherSuite TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = new CipherSuite(0xC02F, nameof(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256), BulkCipherType.AES_128_GCM, HashType.SHA256, KeyExchangeType.Ecdhe, CertificateType.rsa, TlsVersion.Tls12);
        public static readonly CipherSuite TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = new CipherSuite(0xC030, nameof(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384), BulkCipherType.AES_256_GCM, HashType.SHA384, KeyExchangeType.Ecdhe, CertificateType.rsa, TlsVersion.Tls12);
        public static readonly CipherSuite TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = new CipherSuite(0xCCA8, nameof(TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256), BulkCipherType.CHACHA20_POLY1305, HashType.SHA256, KeyExchangeType.Ecdhe, CertificateType.rsa, TlsVersion.Tls12);
        public static readonly CipherSuite TLS_AES_128_GCM_SHA256 = new CipherSuite(0x1301, nameof(TLS_AES_128_GCM_SHA256), BulkCipherType.AES_128_GCM, HashType.SHA256, null, null, TlsVersion.Tls13Draft18);
        public static readonly CipherSuite TLS_AES_256_GCM_SHA384 = new CipherSuite(0x1302, nameof(TLS_AES_256_GCM_SHA384), BulkCipherType.AES_256_GCM, HashType.SHA384, null, null, TlsVersion.Tls13Draft18);
        public static readonly CipherSuite TLS_CHACHA20_POLY1305_SHA256 = new CipherSuite(0x1303, nameof(TLS_CHACHA20_POLY1305_SHA256), BulkCipherType.CHACHA20_POLY1305, HashType.SHA256, null, null, TlsVersion.Tls13Draft18);
    }
}
