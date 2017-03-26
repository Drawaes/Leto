using Leto.Certificates;
using Leto.Hashes;
using System;

namespace Leto.KeyExchanges
{
    public interface IKeyExchange : IDisposable
    {
        bool HasPeerKey { get; }
        bool RequiresServerKeyExchange { get; }
        void SetPeerKey(Span<byte> peerKey, ICertificate certificate, SignatureScheme scheme);
        int KeyExchangeSize { get; }
        int WritePublicKey(Span<byte> keyBuffer);
        NamedGroup NamedGroup { get; }
        void DeriveSecret(IHashProvider hashProvider, HashType hashType, ReadOnlySpan<byte> salt, Span<byte> output);
        void DeriveMasterSecret(IHashProvider hashProvider, HashType hashType, ReadOnlySpan<byte> seed, Span<byte> output);
    }
}
