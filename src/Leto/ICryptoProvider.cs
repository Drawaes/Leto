using Leto.BulkCiphers;
using Leto.CipherSuites;
using Leto.Hashes;
using Leto.KeyExchanges;
using System;

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
