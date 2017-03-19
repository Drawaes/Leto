using Leto.BulkCiphers;
using Leto.Internal;
using Leto.Interop;
using Leto.OpenSsl11.Interop;
using System;
using System.Buffers.Pools;
using System.Runtime.InteropServices;

namespace Leto.OpenSsl11
{
    public sealed class OpenSslBulkKeyProvider : IBulkCipherKeyProvider
    {
        public OpenSslBulkKeyProvider()
        {
        }

        public AeadBulkCipher GetCipher(BulkCipherType cipherType, Memory<byte> keyStorage)
        {
            OpenSslBulkCipherKey key;
            switch (cipherType)
            {
                case BulkCipherType.AES_128_GCM:
                    key = new OpenSslBulkCipherKey(LibCrypto.EVP_aes_128_gcm, keyStorage, 16, 12, 16);
                    break;
                case BulkCipherType.AES_256_GCM:
                    key = new OpenSslBulkCipherKey(LibCrypto.EVP_aes_256_gcm, keyStorage, 32, 12, 16);
                    break;
                case BulkCipherType.CHACHA20_POLY1305:
                    key = new OpenSslBulkCipherKey(LibCrypto.EVP_chacha20_poly1305, keyStorage, 32, 12, 16);
                    break;
                default:
                    ExceptionHelper.ThrowException(new NotImplementedException());
                    return null;
            }
            return new AeadBulkCipher(key);
        }

        public void Dispose()
        {
            //Nothing managed to dispose
        }
    }
}
