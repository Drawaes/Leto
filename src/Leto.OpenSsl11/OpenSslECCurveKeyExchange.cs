using Leto.KeyExchanges;
using System;
using Leto.Hashes;
using static Leto.OpenSsl11.Interop.LibCrypto;
using Leto.Certificates;
using System.Buffers;
using Leto.Internal;

namespace Leto.OpenSsl11
{
    public sealed class OpenSslECCurveKeyExchange : IKeyExchange
    {
        private int _curveNid;
        private int _keyExchangeSize;
        private NamedGroup _namedGroup;
        private EVP_PKEY _peerKey;
        private EVP_PKEY _keyPair;

        public OpenSslECCurveKeyExchange(NamedGroup namedGroup)
        {
            _namedGroup = namedGroup;
            switch (NamedGroup)
            {
                case NamedGroup.secp256r1:
                    _curveNid = OBJ_sn2nid("prime256v1");
                    _keyExchangeSize = 65;
                    break;
                case NamedGroup.secp384r1:
                    _curveNid = OBJ_sn2nid("secp384r1");
                    _keyExchangeSize = 97;
                    break;
                case NamedGroup.secp521r1:
                    _curveNid = OBJ_sn2nid("secp521r1");
                    _keyExchangeSize = 133;
                    break;
                default:
                    ExceptionHelper.ThrowException(new InvalidOperationException());
                    break;
            }
        }

        public int KeyExchangeSize => _keyExchangeSize;
        public NamedGroup NamedGroup => _namedGroup;
        public bool RequiresServerKeyExchange => true;

        public void DeriveMasterSecret(IHashProvider hashProvider, HashType hashType, ReadOnlySpan<byte> seed, Span<byte> output)
        {
            var tempBuffer = new byte[(_keyExchangeSize - 1) / 2];
            var secretSize = EVP_PKEY_derive(_keyPair, _peerKey, tempBuffer);
            var secretSpan = tempBuffer.Slice(0, secretSize);
            hashProvider.Tls12Prf(hashType, secretSpan, TlsConstants.Tls12.Label_MasterSecret, seed, output);
        }
                
        public void SetPeerKey(BigEndianAdvancingSpan peerKey, ICertificate certificate, SignatureScheme scheme)
        {
            peerKey = peerKey.ReadVector<byte>();
            if (peerKey.Length != _keyExchangeSize)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error, "Peer key is bad");
            }
            InternalSetPeerKey(peerKey.ToSpan());
        }

        private void InternalSetPeerKey(Span<byte> peerKey)
        {
            GenerateKeyPair();
            //Get0 methods mean that we do not own the object, and therefore should not free
            //as they belong to another structure so we only need to free the point
            var group = EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(_keyPair));
            var point = EC_POINT_new(group);
            try
            {
                EC_POINT_oct2point(group, point, peerKey);
                var ecKey = EC_KEY_new_by_curve_name(_curveNid);
                try
                {
                    EC_KEY_set_public_key(ecKey, point);
                    _peerKey = EVP_PKEY_new();
                    EVP_PKEY_assign_EC_KEY(_peerKey, ecKey);
                }
                catch
                {
                    //If the ec key was correctly assigned to the EVP_KEY
                    //then it will be freed when we free the EVP_KEY
                    //which now has ownship so we only release if there was an
                    //exception trying to transfer the ownership
                    ecKey.Free();
                    throw;
                }
            }
            finally
            {
                point.Free();
            }
        }

        public int WritePublicKey(Span<byte> keyBuffer)
        {
            GenerateKeyPair();
            //get0 methods return pointers that we do not free because they are owned
            //by other objects
            var key = EVP_PKEY_get0_EC_KEY(_keyPair);
            var pubKey = EC_KEY_get0_public_key(key);
            var group = EC_KEY_get0_group(key);
            return EC_POINT_point2oct(group, pubKey, EC_POINT_CONVERSION.POINT_CONVERSION_UNCOMPRESSED, keyBuffer);
        }

        private void GenerateKeyPair()
        {
            if (_keyPair.IsValid) return;
            EVP_PKEY_paramgen_ECCurve(_curveNid, out EVP_PKEY curveParameters);
            try
            {
                EVP_PKEY_keygen(curveParameters, out _keyPair);
            }
            finally
            {
                curveParameters.Free();
            }
        }

        public void Dispose()
        {
            _keyPair.Free();
            _peerKey.Free();
            GC.SuppressFinalize(this);
        }

        ~OpenSslECCurveKeyExchange() => Dispose();
    }
}
