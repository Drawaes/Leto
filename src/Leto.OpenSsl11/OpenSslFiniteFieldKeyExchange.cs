using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;
using Leto.Certificates;
using Leto.Hashes;
using Leto.Internal;
using Leto.KeyExchanges;
using Leto.OpenSsl11.Internal;
using static Leto.OpenSsl11.Interop.LibCrypto;

namespace Leto.OpenSsl11
{
    public class OpenSslFiniteFieldKeyExchange : IKeyExchange
    {
        private bool _hasPeerKey;
        private int _keyExchangeSize;
        private NamedGroup _namedGroup;
        private DH _localKey;
        private BIGNUM _clientBN;

        public OpenSslFiniteFieldKeyExchange(NamedGroup namedGroup) => _namedGroup = namedGroup;

        public bool HasPeerKey => _hasPeerKey;
        public bool RequiresServerKeyExchange => true;
        public int KeyExchangeSize => _keyExchangeSize;
        public NamedGroup NamedGroup => _namedGroup;

        public void DeriveMasterSecret(IHashProvider hashProvider, HashType hashType, ReadOnlySpan<byte> seed, Span<byte> output)
        {
            var buffer = new byte[_keyExchangeSize];
            var written = DeriveSecret(buffer);
            hashProvider.Tls12Prf(hashType, buffer.Slice(0, written), TlsConstants.Tls12.Label_MasterSecret, seed, output);
        }

        public void DeriveSecret(IHashProvider hashProvider, HashType hashType, ReadOnlySpan<byte> salt, Span<byte> output)
        {
            var buffer = new byte[_keyExchangeSize];
            var written = DeriveSecret(buffer);
            hashProvider.HmacData(hashType, salt, buffer.Slice(0, written), output);
        }

        public int DeriveSecret(Span<byte> buffer)
        {
            try
            {
                return DH_compute_key(buffer, _clientBN, _localKey);
            }
            finally
            {
                Dispose();
            }
        }

        public void SetPeerKey(BigEndianAdvancingSpan peerKey, ICertificate certificate, SignatureScheme scheme)
        {
            peerKey = peerKey.ReadVector<byte>();
            if (peerKey.Length != _keyExchangeSize)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error, "Peer key is bad");
            }
            GenerateKeys(null, null);
            InternalSetPeerKey(peerKey.ToSpan());
        }

        public void SetPeerKey(BigEndianAdvancingSpan peerKey)
        {
            peerKey = peerKey.ReadVector<ushort>();
            if (peerKey.Length != _keyExchangeSize)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error, "Peer key is bad");
            }
            GenerateKeys(null, null);
            InternalSetPeerKey(peerKey.ToSpan());
        }

        private unsafe void InternalSetPeerKey(Span<byte> peerKey)
        {
            _clientBN = BN_bin2bn(peerKey);
            _hasPeerKey = true;
        }

        public unsafe int WritePublicKey(Span<byte> buffer)
        {
            DH_get0_key(_localKey, out BIGNUM pub, out BIGNUM priv);
            if (buffer.Length < _keyExchangeSize) throw new InvalidOperationException();
            return BN_bn2binpad(pub, buffer);
        }

        public unsafe void GenerateKeys(byte[] privateKey, byte[] publicKey)
        {
            if (_localKey.IsAllocated)
            {
                return;
            }
            byte[] q, p;
            byte g;
            switch (_namedGroup)
            {
                case NamedGroup.ffdhe2048:
                    _keyExchangeSize = 256;
                    g = FfdheRfc7919.G2048;
                    q = FfdheRfc7919.Q2048;
                    p = FfdheRfc7919.P2048;
                    break;
                case NamedGroup.ffdhe3072:
                    _keyExchangeSize = 384;
                    g = FfdheRfc7919.G3072;
                    q = FfdheRfc7919.Q3072;
                    p = FfdheRfc7919.P3072;
                    break;
                case NamedGroup.ffdhe4096:
                    _keyExchangeSize = 512;
                    g = FfdheRfc7919.G4096;
                    q = FfdheRfc7919.Q4096;
                    p = FfdheRfc7919.P4096;
                    break;
                case NamedGroup.ffdhe6144:
                    _keyExchangeSize = 768;
                    g = FfdheRfc7919.G6144;
                    q = FfdheRfc7919.Q6144;
                    p = FfdheRfc7919.P6144;
                    break;
                case NamedGroup.ffdhe8192:
                    _keyExchangeSize = 1024;
                    g = FfdheRfc7919.G8192;
                    q = FfdheRfc7919.Q8192;
                    p = FfdheRfc7919.P8192;
                    break;
                default:
                    ExceptionHelper.ThrowException(new ArgumentOutOfRangeException());
                    return;
            }
            var qBN = BN_bin2bn(q);
            var gBN = BN_bin2bn(new Span<byte>(&g, 1));
            var pBN = BN_bin2bn(p);
            _localKey = DH_new();
            DH_set0_pqg(_localKey, pBN, qBN, gBN);
            if (privateKey != null)
            {
                var privBN = BN_bin2bn(privateKey);
                var pubBN = BN_bin2bn(publicKey);
                DH_set0_key(_localKey, pubBN, privBN);
            }
            else
            {
                DH_generate_key(_localKey);
            }
        }

        public void Dispose()
        {
            _localKey.Free();
            _clientBN.Free();
        }

        ~OpenSslFiniteFieldKeyExchange() => Dispose();
    }
}
