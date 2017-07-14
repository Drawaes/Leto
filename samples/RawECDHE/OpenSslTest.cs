using System;
using System.Collections.Generic;
using System.Text;
using static Leto.OpenSsl11.Interop.LibCrypto;

namespace RawECDHE
{
    public class OpenSslTest
    {
        private readonly int _nid;
        private readonly int _keyExchangeSize;

        public OpenSslTest()
        {
            _nid = OBJ_sn2nid("prime256v1");
            _keyExchangeSize = 65;

        }

        public void GeneratePublicKey()
        {
            EVP_PKEY_paramgen_ECCurve(_nid, out EVP_PKEY curveParameters);
            EVP_PKEY_keygen(curveParameters, out EVP_PKEY _keyPair);
            var key = EVP_PKEY_get0_EC_KEY(_keyPair);
            var pubKey = EC_KEY_get0_public_key(key);
            var group = EC_KEY_get0_group(key);
            var tempBuffer = new byte[_keyExchangeSize];
            var length = EC_POINT_point2oct(group, pubKey, EC_POINT_CONVERSION.POINT_CONVERSION_UNCOMPRESSED, tempBuffer);
            Console.WriteLine(BitConverter.ToString(tempBuffer, 0, length));
        }

        public void GenerateSecret(Span<byte> publicKey, Span<byte> output)
        {
            EVP_PKEY_paramgen_ECCurve(_nid, out EVP_PKEY curveParameters);
            EVP_PKEY_keygen(curveParameters, out EVP_PKEY _keyPair);

            var group = EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(_keyPair));
            var point = EC_POINT_new(group);
            EC_POINT_oct2point(group, point, publicKey);
            var ecKey = EC_KEY_new_by_curve_name(_nid);
            EC_KEY_set_public_key(ecKey, point);
            var peerKey = EVP_PKEY_new();
            EVP_PKEY_assign_EC_KEY(peerKey, ecKey);

            point.Free();

            
            var secretSize = EVP_PKEY_derive(_keyPair, peerKey, output);
            _keyPair.Free();
            peerKey.Free();
        }
    }
}
