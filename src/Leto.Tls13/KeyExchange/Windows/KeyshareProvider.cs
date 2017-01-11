using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static Interop.BCrypt;
using Microsoft.Win32.SafeHandles;
using static Leto.Tls13.Interop.Windows.ExceptionHelper;

namespace Leto.Tls13.KeyExchange.Windows
{
    public class KeyshareProvider : IKeyshareProvider
    {
        private SafeBCryptAlgorithmHandle _x25519;
        private SafeBCryptAlgorithmHandle _finite;
        private SafeBCryptAlgorithmHandle _secp256r1;
        private SafeBCryptAlgorithmHandle _secp384r1;
        private SafeBCryptAlgorithmHandle _secp521r1;
        
        public KeyshareProvider()
        {
            _x25519 = GetECProvider("curve25519");
            _secp256r1 = GetECProvider("secP256r1");
            _secp384r1 = GetECProvider("secP384r1");
            _secp521r1 = GetECProvider("secP521r1");
        }

        private SafeBCryptAlgorithmHandle GetECProvider(string curveName)
        {
            SafeBCryptAlgorithmHandle handle;
            CheckReturnCode(BCryptOpenAlgorithmProvider(out handle, "ECDH", null, BCryptOpenAlgorithmProviderFlags.None));
            CheckReturnCode(BCryptSetProperty(handle, BCryptPropertyStrings.BCRYPT_ECC_CURVE_NAME, curveName, (curveName.Length + 1) * sizeof(char), 0));
            return handle;
        }

        public void Dispose()
        {
            _x25519?.Dispose();
            _finite?.Dispose();
            _secp256r1?.Dispose();
            _secp384r1?.Dispose();
            _secp521r1?.Dispose();
        }

        public IKeyshareInstance GetKeyShareInstance(NamedGroup namedGroup)
        {
            switch(namedGroup)
            {
                case NamedGroup.secp256r1:
                    return new ECCurveInstance(_secp256r1, namedGroup, 65);
                case NamedGroup.secp384r1:
                    return new ECCurveInstance(_secp384r1, namedGroup, 97);
                case NamedGroup.secp521r1:
                    return new ECCurveInstance(_secp521r1, namedGroup, 133);
                case NamedGroup.x25519:
                    return null;
                default:
                    return null;
            }
        }
    }
}
