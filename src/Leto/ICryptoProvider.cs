using Leto.CipherSuites;
using Leto.Handshake;
using Leto.Keyshares;
using System;
using System.Collections.Generic;
using System.Text;

namespace Leto
{
    public interface ICryptoProvider
    {
        CipherSuiteProvider CipherSuites { get; }
        IKeyshareProvider KeyshareProvider { get; }

        void FillWithRandom(Span<byte> span);
    }
}
