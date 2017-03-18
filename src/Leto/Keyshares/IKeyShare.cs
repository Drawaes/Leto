using Leto.Hashes;
using System;

namespace Leto.Keyshares
{
    public interface IKeyshare : IDisposable
    {
        bool HasPeerKey { get; }
        bool RequiresServerKeyExchange { get; }
        void SetPeerKey(ReadOnlySpan<byte> peerKey);
        int KeyExchangeSize { get; }
        int WritePublicKey(Span<byte> keyBuffer);
        NamedGroup NamedGroup { get; }
        void DeriveSecret(IHashProvider hashProvider, HashType hashType, ReadOnlySpan<byte> salt, Span<byte> output);
        void DeriveMasterSecret(IHashProvider hashProvider, HashType hashType, ReadOnlySpan<byte> seed, Span<byte> output);
    }
}
