using Leto.Certificates;
using Leto.Keyshares;
using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.OpenSsl11
{
    public sealed class OpenSslKeyshareProvider : IKeyshareProvider
    {
        private ICertificate _certificate;

        public OpenSslKeyshareProvider(ICertificate certificate)
        {
            _certificate = certificate;
        }

        /// <summary>
        /// Tls 1.3 and onwards keyshare selection
        /// </summary>
        public IKeyshare GetKeyshare(NamedGroup namedGroup)
        {
            switch (namedGroup)
            {
                case NamedGroup.secp256r1:
                case NamedGroup.secp384r1:
                case NamedGroup.secp521r1:
                    return new OpenSslECCurveKeyshare(namedGroup);
                case NamedGroup.ffdhe2048:
                case NamedGroup.ffdhe3072:
                case NamedGroup.ffdhe4096:
                case NamedGroup.ffdhe6144:
                case NamedGroup.ffdhe8192:
                case NamedGroup.x25519:
                case NamedGroup.x448:
                default:
                    return null;
            }
        }

        /// <summary>
        /// Heritagae keyshare selection (pre tls 1.3)
        /// </summary>
        /// <param name="keyExchange"></param>
        /// <param name="supportedGroups"></param>
        /// <returns></returns>
        public IKeyshare GetKeyshare(KeyExchangeType keyExchange, Span<byte> supportedGroups)
        {
            switch(keyExchange)
            {
                case KeyExchangeType.Rsa:
                    return new OpenSslRsaKeyshare();
                default:
                    Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure, "Unable to match key exchange");
                    return null;
            }
        }

        public void Dispose()
        {
            //No resources currently to clean up
        }
    }
}
