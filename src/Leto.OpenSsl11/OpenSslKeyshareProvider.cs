using Leto.Certificates;
using Leto.Keyshares;
using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.OpenSsl11
{
    public sealed class OpenSslKeyshareProvider : IKeyshareProvider
    {
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
                case NamedGroup.x25519:
                case NamedGroup.x448:
                    return new OpenSslECFunctionKeyshare(namedGroup);
                case NamedGroup.ffdhe2048:
                case NamedGroup.ffdhe3072:
                case NamedGroup.ffdhe4096:
                case NamedGroup.ffdhe6144:
                case NamedGroup.ffdhe8192:
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
                    return new RsaKeyshare();
                case KeyExchangeType.Ecdhe:
                    //need to check the supported groups to check if we are going to use
                    //a named curve function or a named curve
                    return EcdheKeyshare(supportedGroups);
                default:
                    Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure, "Unable to match key exchange");
                    return null;
            }
        }

        private IKeyshare EcdheKeyshare(Span<byte> supportedGroups)
        {
            supportedGroups = BufferExtensions.ReadVector16(ref supportedGroups);
            while(supportedGroups.Length >0)
            {
                var namedGroup = BufferExtensions.ReadBigEndian<NamedGroup>(ref supportedGroups);
                switch(namedGroup)
                {
                    case NamedGroup.secp256r1:
                    case NamedGroup.secp384r1:
                    case NamedGroup.secp521r1:
                        return new OpenSslECCurveKeyshare(namedGroup);
                    case NamedGroup.x25519:
                    case NamedGroup.x448:
                        return new OpenSslECFunctionKeyshare(namedGroup);
                }
            }
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure, "Unable to match key exchange");
            return null;
        }

        public void Dispose()
        {
            //No resources currently to clean up
        }
    }
}
