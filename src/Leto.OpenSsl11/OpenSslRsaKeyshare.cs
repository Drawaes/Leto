using Leto.Keyshares;
using System;
using System.Collections.Generic;
using System.Text;
using Leto.Hashes;
using Leto.Certificates;

namespace Leto.OpenSsl11
{
    public class OpenSslRsaKeyshare : IKeyshare
    {
        private byte[] _premasterSecret;

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
            //Nothing to cleanup in the case of a basic key exchange
        }

        public void SetPeerKey(Span<byte> peerKey, ICertificate certificate, SignatureScheme scheme)
        {
            peerKey = BufferExtensions.ReadVector16(ref peerKey);
            var decryptedLength = certificate.Decrypt(scheme, peerKey, peerKey );
            peerKey = peerKey.Slice(0, decryptedLength);
            _premasterSecret = peerKey.Slice(2).ToArray();
        }

        public int WritePublicKey(Span<byte> keyBuffer)
        {
            throw new NotImplementedException();
        }
    }
}
