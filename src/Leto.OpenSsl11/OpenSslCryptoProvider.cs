using Leto.Keyshares;
using System;
using System.Collections.Generic;
using System.Text;
using static Leto.BufferExtensions;
using Leto.CipherSuites;
using Leto.Certificates;
using static Leto.OpenSsl11.Interop.LibCrypto;
using Leto.Hashes;

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
        private ICertificate _certificate;
        private IHashProvider _hashProvider;

        public OpenSslCryptoProvider(ICertificate certificate)
        {
            _certificate = certificate;
            _hashProvider = new OpenSslHashProvider();
            _keyshareProvider = new OpenSslKeyshareProvider(_certificate);
        }

        public IKeyshareProvider KeyshareProvider => _keyshareProvider;
        public CipherSuiteProvider CipherSuites => _cipherSuites;
        public ICertificate Certificate => _certificate;
        public IHashProvider HashProvider => _hashProvider;

        public void FillWithRandom(Span<byte> span) => RAND_bytes(span);
    }
}
