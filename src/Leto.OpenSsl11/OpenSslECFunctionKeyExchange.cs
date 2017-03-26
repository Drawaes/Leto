using Leto.KeyExchanges;
using System;
using Leto.Hashes;
using static Leto.OpenSsl11.Interop.LibCrypto;
using Leto.Certificates;

namespace Leto.OpenSsl11
{
    public sealed class OpenSslECFunctionKeyExchange : IKeyExchange
    {
        private int _nid;
        private int _keyExchangeSize;
        private NamedGroup _namedGroup;
        private EVP_PKEY _peerKey;
        private EVP_PKEY _keyPair;

        public OpenSslECFunctionKeyExchange(NamedGroup namedGroup)
        {
            _namedGroup = namedGroup;
            switch (namedGroup)
            {
                case NamedGroup.x25519:
                    _keyExchangeSize = 32;
                    _nid = OBJ_sn2nid("X25519");
                    break;
                case NamedGroup.x448:
                    _keyExchangeSize = 56;
                    _nid = OBJ_sn2nid("X448");
                    break;
                default:
                    ExceptionHelper.ThrowException(new InvalidOperationException());
                    break;
            }
        }

        public bool HasPeerKey => _peerKey.IsValid;
        public int KeyExchangeSize => _keyExchangeSize;
        public NamedGroup NamedGroup => _namedGroup;
        public bool RequiresServerKeyExchange => true;

        public void DeriveMasterSecret(IHashProvider hashProvider, HashType hashType, ReadOnlySpan<byte> seed, Span<byte> output)
        {
            var tempBuffer = new byte[_keyExchangeSize];
            var secretSize = EVP_PKEY_derive(_keyPair, _peerKey, tempBuffer);
            var secretSpan = tempBuffer.Slice(0, secretSize);
            hashProvider.Tls12Prf(hashType, secretSpan, TlsConstants.Tls12.Label_MasterSecret, seed, output);
            System.Diagnostics.Debug.WriteLine(BitConverter.ToString(output.ToArray()));
        }

        public void DeriveSecret(IHashProvider hashProvider, HashType hashType, ReadOnlySpan<byte> salt, Span<byte> output)
        {
            var tempBuffer = new byte[_keyExchangeSize];
            var secretSize = EVP_PKEY_derive(_keyPair, _peerKey, tempBuffer);
            var secretSpan = tempBuffer.Slice(0, secretSize);
            hashProvider.HmacData(hashType, salt, secretSpan, output);
        }

        public void SetPeerKey(Span<byte> peerKey, ICertificate certificate, SignatureScheme scheme)
        {
            peerKey = BufferExtensions.ReadVector8(ref peerKey);
            if (peerKey.Length != _keyExchangeSize)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.illegal_parameter, $"The peer key is not the length of the keyexchange size {peerKey.Length} - {_keyExchangeSize}");
            }
            _peerKey = EVP_PKEY_new();
            EVP_PKEY_set_type(_peerKey, _nid);
            EVP_PKEY_set1_tls_encodedpoint(_peerKey, peerKey);
            GenerateKeyPair();
        }

        public int WritePublicKey(Span<byte> keyBuffer)
        {
            GenerateKeyPair();
            return EVP_PKEY_get1_tls_encodedpoint(_keyPair, keyBuffer);
        }

        private void GenerateKeyPair()
        {
            if (_keyPair.IsValid) return;
            EVP_PKEY_keygen_function(_nid, out _keyPair);
        }

        public void Dispose()
        {
            _keyPair.Free();
            _peerKey.Free();
            GC.SuppressFinalize(this);
        }

        ~OpenSslECFunctionKeyExchange()
        {
            Dispose();
        }
    }
}
