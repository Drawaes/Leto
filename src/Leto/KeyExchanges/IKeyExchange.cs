using Leto.Certificates;
using Leto.Hashes;
using System;
using Leto.Internal;

namespace Leto.KeyExchanges
{
    public interface IKeyExchange : IDisposable
    {
        bool RequiresServerKeyExchange { get; }
        void SetPeerKey(BigEndianAdvancingSpan peerKey, ICertificate certificate, SignatureScheme scheme);
        int KeyExchangeSize { get; }
        int WritePublicKey(Span<byte> keyBuffer);
        NamedGroup NamedGroup { get; }
        void DeriveMasterSecret(IHashProvider hashProvider, HashType hashType, ReadOnlySpan<byte> seed, Span<byte> output);
    }
}
