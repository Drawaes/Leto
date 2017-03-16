using Leto.Keyshares;
using System;
using System.Collections.Generic;
using System.Text;
using Leto.Hashes;

namespace Leto.OpenSsl11
{
    public class OpenSslRsaKeyshare : IKeyshare
    {
        public bool HasPeerKey => throw new NotImplementedException();

        public int KeyExchangeSize => throw new NotImplementedException();

        public NamedGroup NamedGroup => throw new NotImplementedException();

        public void DeriveMasterSecret(IHashProvider hashProvider, HashType hashType, ReadOnlySpan<byte> seed, Span<byte> output)
        {
            throw new NotImplementedException();
        }

        public void DeriveSecret(IHashProvider hashProvider, HashType hashType, ReadOnlySpan<byte> salt, Span<byte> output)
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }

        public void SetPeerKey(ReadOnlySpan<byte> peerKey)
        {
            throw new NotImplementedException();
        }

        public int WritePublicKey(Span<byte> keyBuffer)
        {
            throw new NotImplementedException();
        }
    }
}
