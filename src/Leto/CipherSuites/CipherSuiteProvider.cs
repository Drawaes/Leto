using System;
using System.Collections.Generic;
using Leto.Internal;
using static Leto.BufferExtensions;

namespace Leto.CipherSuites
{
    public class CipherSuiteProvider
    {
        private CipherSuite[] _cipherSuites;

        public CipherSuiteProvider(CipherSuite[] cipherSuites) => _cipherSuites = cipherSuites;

        public CipherSuite GetCipherSuite(ushort cipherSuite)
        {
            for (var i = 0; i < _cipherSuites.Length; i++)
            {
                if (_cipherSuites[i].Code == cipherSuite)
                {
                    return _cipherSuites[i];
                }
            }
            return null;
        }

        public CipherSuite GetCipherSuite(TlsVersion tlsVersion, BigEndianAdvancingSpan cipherSuites)
        {
            for (var x = 0; x < _cipherSuites.Length; x++)
            {
                var tempSpan = cipherSuites;
                while (tempSpan.Length > 0)
                {
                    var cipherSuite = tempSpan.Read<ushort>();
                    if (cipherSuite == _cipherSuites[x].Code)
                    {
                        if (_cipherSuites[x].SupportsVersion(tlsVersion))
                        {
                            return _cipherSuites[x];
                        }
                    }
                }
            }
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure, "Unable to match");
            return null;
        }
    }
}
