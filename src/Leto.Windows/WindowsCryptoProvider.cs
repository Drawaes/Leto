using System;
using System.Collections.Generic;
using System.Text;
using Leto.BulkCiphers;
using Leto.CipherSuites;
using Leto.Hashes;
using Leto.KeyExchanges;
using Leto.Windows.Interop;

namespace Leto.Windows
{
    public class WindowsCryptoProvider : ICryptoProvider, IDisposable
    {
        private CipherSuiteProvider _cipherSuites = new CipherSuiteProvider(new CipherSuite[]
        {
            PredefinedCipherSuites.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            PredefinedCipherSuites.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            PredefinedCipherSuites.RSA_AES_128_GCM_SHA256,
            PredefinedCipherSuites.RSA_AES_256_GCM_SHA384,
            PredefinedCipherSuites.TLS_AES_128_GCM_SHA256,
            PredefinedCipherSuites.TLS_AES_256_GCM_SHA384,
        });
        private WindowsKeyExchangeProvider _keyExchangeProvider;
        private WindowsHashProvider _hashProvider;
        private WindowsBulkKeyProvider _bulkCipherProvider;

        public WindowsCryptoProvider()
        {
            _hashProvider = new WindowsHashProvider();
            _keyExchangeProvider = new WindowsKeyExchangeProvider();
            _bulkCipherProvider = new WindowsBulkKeyProvider();
        }

        public IKeyExchangeProvider KeyExchangeProvider => _keyExchangeProvider;
        public CipherSuiteProvider CipherSuites => _cipherSuites;
        public IHashProvider HashProvider => _hashProvider;
        public IBulkCipherKeyProvider BulkCipherProvider => _bulkCipherProvider;

        public void FillWithRandom(Span<byte> span) => BCrypt.BCryptGenRandom(span);

        public void Dispose()
        {
            _keyExchangeProvider?.Dispose();
            _keyExchangeProvider = null;
            _hashProvider?.Dispose();
            _hashProvider = null;
            _bulkCipherProvider?.Dispose();
            _bulkCipherProvider = null;

            GC.SuppressFinalize(this);
        }

        ~WindowsCryptoProvider()
        {
            Dispose();
        }
    }
}
