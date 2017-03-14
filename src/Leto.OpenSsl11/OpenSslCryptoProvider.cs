using Leto.Keyshares;
using System;
using System.Collections.Generic;
using System.Text;
using static Leto.BufferExtensions;
using Leto.CipherSuites;

namespace Leto.OpenSsl11
{
    public class OpenSslCryptoProvider : ICryptoProvider
    {
        private CipherSuiteProvider _cipherSuites = new CipherSuiteProvider(new CipherSuite[]
        {
            PredefinedCipherSuites.RSA_AES_GCM_SHA256,
            PredefinedCipherSuites.RSA_AES_GCM_SHA384
        });
        
        public CipherSuiteProvider CipherSuites => _cipherSuites;
    }
}
