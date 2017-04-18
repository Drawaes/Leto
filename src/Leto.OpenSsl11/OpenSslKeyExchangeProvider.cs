using Leto.KeyExchanges;
using System;
using Leto.Internal;
using System.Collections.Generic;
using System.Linq;

namespace Leto.OpenSsl11
{
    public sealed class OpenSslKeyExchangeProvider : IKeyExchangeProvider
    {
        private List<NamedGroup> _supportedNamedGroups = new List<NamedGroup>()
        {
            NamedGroup.ffdhe2048,
            NamedGroup.ffdhe3072,
            NamedGroup.ffdhe4096,
            NamedGroup.ffdhe6144,
            NamedGroup.ffdhe8192,
            NamedGroup.ffdhe8192,
            NamedGroup.secp256r1,
            NamedGroup.secp384r1,
            NamedGroup.secp521r1,
            NamedGroup.x25519,
            NamedGroup.x448
        };

        public void SetSupportedNamedGroups(params NamedGroup[] namedGroups) => _supportedNamedGroups = namedGroups.ToList();

        public IKeyExchange GetKeyExchangeFromSupportedGroups(BigEndianAdvancingSpan supportedGroups)
        {
            supportedGroups = supportedGroups.ReadVector<ushort>();
            while (supportedGroups.Length > 0)
            {
                var namedGroup = supportedGroups.Read<NamedGroup>();
                var keyExchange = GetKeyExchange(namedGroup);
                if (keyExchange != null) return keyExchange;
            }
            return null;
        }

        /// <summary>
        /// Tls 1.3 and onwards KeyExchange selection
        /// </summary>
        public IKeyExchange GetKeyExchange(NamedGroup namedGroup)
        {
            if(!_supportedNamedGroups.Contains(namedGroup))
            {
                return null;
            }
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
                    return new OpenSslFiniteFieldKeyExchange(namedGroup);
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
        public IKeyExchange GetKeyExchange(KeyExchangeType keyExchange, BigEndianAdvancingSpan supportedGroups)
        {
            switch (keyExchange)
            {
                case KeyExchangeType.Rsa:
                    return new RsaKeyExchange();
                case KeyExchangeType.Ecdhe:
                case KeyExchangeType.Dhe:
                    //need to check the supported groups to check if we are going to use
                    //a named curve function or a named curve
                    return EcdheKeyExchange(supportedGroups);
                default:
                    Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure, "Unable to match key exchange");
                    return null;
            }
        }

        private IKeyExchange EcdheKeyExchange(BigEndianAdvancingSpan supportedGroups)
        {
            supportedGroups = supportedGroups.ReadVector<ushort>();
            while (supportedGroups.Length > 0)
            {
                var namedGroup = supportedGroups.Read<NamedGroup>();
                var keyExchange = GetKeyExchange(namedGroup);
                if (keyExchange != null) return keyExchange;
            }
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure, "Unable to match key exchange");
            return null;
        }

        public void Dispose()
        {
            //No resources currently to clean up
        }

        public IKeyExchange GetKeyExchange(BigEndianAdvancingSpan keyshare)
        {
            while (keyshare.Length > 0)
            {
                var key = keyshare.ReadVector<ushort>();
                var namedGroup = key.Read<NamedGroup>();
                var instance = GetKeyExchange(namedGroup);
                if (instance != null)
                {
                    instance.SetPeerKey(key);
                    return instance;
                }
            }
            return null;
        }


    }
}
