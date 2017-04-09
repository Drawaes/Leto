using Leto.Certificates;
using Leto.Hashes;
using System;
using System.Collections.Generic;
using System.Text;
using Leto.Internal;

namespace Leto.KeyExchanges
{
    public class RsaKeyExchange : IKeyExchange
    {
        private byte[] _premasterSecret;

        public bool HasPeerKey => false;
        public bool RequiresServerKeyExchange => false;
        public int KeyExchangeSize => 0;

        public NamedGroup NamedGroup => NamedGroup.None;

        public void DeriveMasterSecret(IHashProvider hashProvider, HashType hashType, ReadOnlySpan<byte> seed, Span<byte> output) =>
            hashProvider.Tls12Prf(hashType, _premasterSecret, TlsConstants.Tls12.Label_MasterSecret, seed, output);

        public void DeriveSecret(IHashProvider hashProvider, HashType hashType, ReadOnlySpan<byte> salt, Span<byte> output) =>
            throw new NotImplementedException();

        public void Dispose()
        {
            //Nothing to cleanup in the case of a basic key exchange
        }

        public void SetPeerKey(BigEndianAdvancingSpan peerKey, ICertificate certificate, SignatureScheme scheme)
        {
            peerKey = peerKey.ReadVector<ushort>();
            var decryptedLength = certificate.Decrypt(scheme, peerKey.ToSpan(), peerKey.ToSpan());
            peerKey = peerKey.TakeSlice(decryptedLength);
            _premasterSecret = peerKey.ToArray();
        }

        public int WritePublicKey(Span<byte> keyBuffer) => throw new NotImplementedException();
    }
}
