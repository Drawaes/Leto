using Leto.BulkCiphers;
using System;
using System.Buffers;
using static Leto.OpenSsl11.Interop.LibCrypto;

namespace Leto.OpenSsl11
{
    public sealed class OpenSslBulkKeyProvider : IBulkCipherKeyProvider
    {
        private (int keySize, int ivSize, EVP_BulkCipher_Type bulkCipher) GetCipher(BulkCipherType cipherType)
        {
            switch (cipherType)
            {
                case BulkCipherType.AES_128_GCM:
                    return (16, 12, EVP_aes_128_gcm);
                case BulkCipherType.AES_256_GCM:
                    return (32, 12, EVP_aes_256_gcm);
                case BulkCipherType.CHACHA20_POLY1305:
                    return (32, 12, EVP_chacha20_poly1305);
                default:
                    throw new NotImplementedException();
            }
        }

        public T GetCipher<T>(BulkCipherType cipherType, OwnedBuffer<byte> keyStorage) where T : AeadBulkCipher, new()
        {
            var (keySize, ivSize, bulkCipher) = GetCipher(cipherType);
            var key = new OpenSslBulkCipherKey(bulkCipher, keyStorage, keySize, ivSize, 16);
            var returnValue = new T();
            returnValue.SetKey(key);
            return returnValue;
        }

        public void Dispose()
        {
            //Nothing managed to dispose
        }

        public (int keySize, int ivSize) GetCipherSize(BulkCipherType cipherType)
        {
            var (keySize, ivSize, cipher) = GetCipher(cipherType);
            return (keySize, ivSize);
        }
    }
}
