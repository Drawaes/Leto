using Leto.Keyshares;
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
            PredefinedCipherSuites.RSA_AES_128_GCM_SHA256,
            PredefinedCipherSuites.RSA_AES_256_GCM_SHA384,
        });
        private OpenSslKeyshareProvider _keyshareProvider;
        private IHashProvider _hashProvider;
        private IBulkCipherKeyProvider _bulkCipherProvider;

        public OpenSslCryptoProvider()
        {
            _hashProvider = new OpenSslHashProvider();
            _keyshareProvider = new OpenSslKeyshareProvider();
            _bulkCipherProvider = new OpenSslBulkKeyProvider();
        }

        public IKeyshareProvider KeyshareProvider => _keyshareProvider;
        public CipherSuiteProvider CipherSuites => _cipherSuites;
        public IHashProvider HashProvider => _hashProvider;
        public IBulkCipherKeyProvider BulkCipherProvider => _bulkCipherProvider;
        public void FillWithRandom(Span<byte> span) => RAND_bytes(span);
    }
}
