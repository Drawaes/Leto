using Leto.Keyshares;
using System;
using System.Collections.Generic;
using System.Text;
using Leto.Hashes;

namespace Leto.OpenSsl11
{
    public class OpenSslRsaKeyshare : IKeyshare
    {
        public bool HasPeerKey => false;
        public bool RequiresServerKeyExchange => false;
        public int KeyExchangeSize => 0;

        public NamedGroup NamedGroup => NamedGroup.None;

        public void DeriveMasterSecret(IHashProvider hashProvider, HashType hashType, ReadOnlySpan<byte> seed, Span<byte> output)
        {
        }

        public void DeriveSecret(IHashProvider hashProvider, HashType hashType, ReadOnlySpan<byte> salt, Span<byte> output)
        {
        }

        public void Dispose()
        {
        }

        public void SetPeerKey(ReadOnlySpan<byte> peerKey)
        {
        }

        public int WritePublicKey(Span<byte> keyBuffer)
        {
            throw new NotImplementedException();
        }
    }
}
