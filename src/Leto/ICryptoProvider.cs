using Leto.BulkCiphers;
using Leto.CipherSuites;
using Leto.Handshake;
using Leto.Hashes;
using Leto.KeyExchanges;
using System;
using System.Collections.Generic;
using System.Text;

namespace Leto
{
    public interface ICryptoProvider
    {
        CipherSuiteProvider CipherSuites { get; }
        IKeyExchangeProvider KeyExchangeProvider { get; }
        IHashProvider HashProvider { get; }
        IBulkCipherKeyProvider BulkCipherProvider { get; }
        void FillWithRandom(Span<byte> span);
    }
}
