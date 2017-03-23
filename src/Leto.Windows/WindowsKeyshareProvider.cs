using Leto.Keyshares;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using static Leto.Windows.Interop.BCrypt;

namespace Leto.Windows
{
    public class WindowsKeyshareProvider : IKeyshareProvider
    {
        private SafeBCryptAlgorithmHandle _secp256r1;
        private SafeBCryptAlgorithmHandle _secp384r1;
        private SafeBCryptAlgorithmHandle _secp521r1;

        public WindowsKeyshareProvider()
        {
            _secp256r1 = BCryptOpenECCurveAlgorithmProvider("secP256r1");
            _secp384r1 = BCryptOpenECCurveAlgorithmProvider("secP384r1");
            _secp521r1 = BCryptOpenECCurveAlgorithmProvider("secP521r1");
        }

        public IKeyshare GetKeyshare(NamedGroup namedGroup)
        {
            switch (namedGroup)
            {
                case NamedGroup.secp256r1:
                    return new WindowsECCurveKeyshare(_secp256r1, namedGroup);
                case NamedGroup.secp384r1:
                    return new WindowsECCurveKeyshare(_secp384r1, namedGroup);
                case NamedGroup.secp521r1:
                    return new WindowsECCurveKeyshare(_secp521r1, namedGroup);
                case NamedGroup.x25519:
                case NamedGroup.x448:
                case NamedGroup.ffdhe2048:
                case NamedGroup.ffdhe3072:
                case NamedGroup.ffdhe4096:
                case NamedGroup.ffdhe6144:
                case NamedGroup.ffdhe8192:
                default:
                    return null;
            }
        }

        public IKeyshare GetKeyshare(KeyExchangeType keyExchange, Span<byte> supportedGroups)
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            _secp256r1?.Dispose();
            _secp256r1 = null;
            _secp384r1?.Dispose();
            _secp384r1 = null;
            _secp521r1?.Dispose();
            _secp521r1 = null;
            GC.SuppressFinalize(this);
        }

        ~WindowsKeyshareProvider()
        {
            Dispose();
        }
    }
}
