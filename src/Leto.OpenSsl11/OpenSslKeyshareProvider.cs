﻿using Leto.Keyshares;
using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.OpenSsl11
{
    public sealed class OpenSslKeyshareProvider : IKeyshareProvider
    {
        public IKeyshare GetKeyShare(NamedGroup namedGroup)
        {
            switch (namedGroup)
            {
                case NamedGroup.ffdhe2048:
                case NamedGroup.ffdhe3072:
                case NamedGroup.ffdhe4096:
                case NamedGroup.ffdhe6144:
                case NamedGroup.ffdhe8192:
                    return new FiniteFieldKeyshare(namedGroup);
                case NamedGroup.secp256r1:
                    return new OpenSslECCurveKeyshare(namedGroup);
                case NamedGroup.x25519:
                case NamedGroup.x448:
                    return new ECFunctionKeyshare(namedGroup);
                default:
                    return null;
            }
        }

        public void Dispose()
        {
            //No resources currently to clean up
        }
    }
}