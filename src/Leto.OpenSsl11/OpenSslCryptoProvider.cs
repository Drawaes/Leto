using Leto.Keyshares;
using System;
using System.Collections.Generic;
using System.Text;
using static Leto.BufferExtensions;
using Leto.CipherSuites;
using Leto.Certificates;
using static Leto.OpenSsl11.Interop.LibCrypto;

namespace Leto.OpenSsl11
{
    public class OpenSslCryptoProvider : ICryptoProvider
    {
        private CipherSuiteProvider _cipherSuites = new CipherSuiteProvider(new CipherSuite[]
        {
            PredefinedCipherSuites.RSA_AES_GCM_SHA256,
            PredefinedCipherSuites.RSA_AES_GCM_SHA384
        });
        private OpenSslKeyshareProvider _keyshareProvider;
        private ICertificate _certificate;

        public OpenSslCryptoProvider(ICertificate certificate)
        {
            _certificate = certificate;
             _keyshareProvider = new OpenSslKeyshareProvider(_certificate);
        }

        public IKeyshareProvider KeyshareProvider => _keyshareProvider;
        public CipherSuiteProvider CipherSuites => _cipherSuites;
        public ICertificate Certificate => _certificate;

        public void FillWithRandom(Span<byte> span) => RAND_bytes(span);
    }
}
