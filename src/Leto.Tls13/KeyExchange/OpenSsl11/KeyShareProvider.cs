using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static Interop.LibCrypto;

namespace Leto.Tls13.KeyExchange.OpenSsl11
{
    public class KeyshareProvider : IKeyshareProvider
    {
        private BIGNUM _numberTwo;

        public unsafe KeyshareProvider()
        {
            byte val = 2;
            _numberTwo = BN_bin2bn(&val, 1, IntPtr.Zero);
        }

        public IKeyshareInstance GetKeyShareInstance(NamedGroup namedGroup)
        {
            switch (namedGroup)
            {
                case NamedGroup.ffdhe2048:
                case NamedGroup.ffdhe3072:
                case NamedGroup.ffdhe4096:
                case NamedGroup.ffdhe6144:
                case NamedGroup.ffdhe8192:
                    return new FiniteFieldInstance(namedGroup);
                case NamedGroup.secp256r1:
                case NamedGroup.secp384r1:
                case NamedGroup.secp521r1:
                    return new ECCurveInstance(namedGroup);
                case NamedGroup.x25519:
                case NamedGroup.x448:
                    return new ECFunctionInstance(namedGroup);
                default:
                    return null;
            }
        }

        public void Dispose()
        {
            _numberTwo.Free();
        }

        ~KeyshareProvider()
        {
            Dispose();
        }
    }
}
