using Leto.KeyExchanges;
using System;

namespace Leto.OpenSsl11
{
    public sealed class OpenSslKeyExchangeProvider : IKeyExchangeProvider
    {
        public IKeyExchange GetKeyExchangeFromSupportedGroups(Span<byte> supportedGroups)
        {
            supportedGroups = BufferExtensions.ReadVector16(ref supportedGroups);
            while (supportedGroups.Length > 0)
            {
                var namedGroup = BufferExtensions.ReadBigEndian<NamedGroup>(ref supportedGroups);
                switch (namedGroup)
                {
                    case NamedGroup.secp256r1:
                    case NamedGroup.secp384r1:
                    case NamedGroup.secp521r1:
                        return new OpenSslECCurveKeyExchange(namedGroup);
                    case NamedGroup.x25519:
                    case NamedGroup.x448:
                        return new OpenSslECFunctionKeyExchange(namedGroup);
                }
            }
            return null;
        }

        /// <summary>
        /// Tls 1.3 and onwards KeyExchange selection
        /// </summary>
        public IKeyExchange GetKeyExchange(NamedGroup namedGroup)
        {
            switch (namedGroup)
            {
                case NamedGroup.secp256r1:
                case NamedGroup.secp384r1:
                case NamedGroup.secp521r1:
                    return new OpenSslECCurveKeyExchange(namedGroup);
                case NamedGroup.x25519:
                case NamedGroup.x448:
                    return new OpenSslECFunctionKeyExchange(namedGroup);
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
        /// Heritagae KeyExchange selection (pre tls 1.3)
        /// </summary>
        /// <param name="keyExchange"></param>
        /// <param name="supportedGroups"></param>
        /// <returns></returns>
        public IKeyExchange GetKeyExchange(KeyExchangeType keyExchange, Span<byte> supportedGroups)
        {
            switch (keyExchange)
            {
                case KeyExchangeType.Rsa:
                    return new RsaKeyExchange();
                case KeyExchangeType.Ecdhe:
                    //need to check the supported groups to check if we are going to use
                    //a named curve function or a named curve
                    return EcdheKeyExchange(supportedGroups);
                default:
                    Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure, "Unable to match key exchange");
                    return null;
            }
        }

        private IKeyExchange EcdheKeyExchange(Span<byte> supportedGroups)
        {
            supportedGroups = BufferExtensions.ReadVector16(ref supportedGroups);
            while (supportedGroups.Length > 0)
            {
                var namedGroup = BufferExtensions.ReadBigEndian<NamedGroup>(ref supportedGroups);
                switch (namedGroup)
                {
                    case NamedGroup.secp256r1:
                    case NamedGroup.secp384r1:
                    case NamedGroup.secp521r1:
                        return new OpenSslECCurveKeyExchange(namedGroup);
                    case NamedGroup.x25519:
                    case NamedGroup.x448:
                        return new OpenSslECFunctionKeyExchange(namedGroup);
                }
            }
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure, "Unable to match key exchange");
            return null;
        }

        public void Dispose()
        {
            //No resources currently to clean up
        }

        public IKeyExchange GetKeyExchange(Span<byte> keyshare) => throw new NotImplementedException();
    }
}
