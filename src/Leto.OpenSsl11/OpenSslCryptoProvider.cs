using Leto.KeyExchanges;
using System;
using System.Collections.Generic;
using System.Text;
using static Leto.BufferExtensions;
using Leto.CipherSuites;
using Leto.Certificates;
using static Leto.OpenSsl11.Interop.LibCrypto;
using Leto.Hashes;
using Leto.BulkCiphers;

namespace Leto.OpenSsl11
{
    public class OpenSslCryptoProvider : ICryptoProvider
    {
        private CipherSuiteProvider _cipherSuites = new CipherSuiteProvider(new CipherSuite[]
        {
            PredefinedCipherSuites.TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256,
            PredefinedCipherSuites.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            PredefinedCipherSuites.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            PredefinedCipherSuites.RSA_AES_128_GCM_SHA256,
            PredefinedCipherSuites.RSA_AES_256_GCM_SHA384,
            PredefinedCipherSuites.TLS_AES_128_GCM_SHA256,
            PredefinedCipherSuites.TLS_AES_256_GCM_SHA384,
            PredefinedCipherSuites.TLS_CHACHA20_POLY1305_SHA256,
        });
        private OpenSslKeyExchangeProvider _keyExchangeProvider;
        private IHashProvider _hashProvider;
        private IBulkCipherKeyProvider _bulkCipherProvider;

        public OpenSslCryptoProvider()
        {
            _hashProvider = new OpenSslHashProvider();
            _keyExchangeProvider = new OpenSslKeyExchangeProvider();
            _bulkCipherProvider = new OpenSslBulkKeyProvider();
        }

        public IKeyExchangeProvider KeyExchangeProvider => _keyExchangeProvider;
        public CipherSuiteProvider CipherSuites => _cipherSuites;
        public IHashProvider HashProvider => _hashProvider;
        public IBulkCipherKeyProvider BulkCipherProvider => _bulkCipherProvider;
        public virtual void FillWithRandom(Span<byte> span) => RAND_bytes(span);
    }
}
