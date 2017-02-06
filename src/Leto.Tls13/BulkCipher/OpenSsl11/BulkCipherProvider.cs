using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.Internal;
using static Interop.LibCrypto;

namespace Leto.Tls13.BulkCipher.OpenSsl11
{
    public class BulkCipherProvider:IBulkCipherProvider
    {
        private const int MaxBufferSize = 32 + 12 + 12;
        private readonly EphemeralBufferPoolWindows _bufferPool = new EphemeralBufferPoolWindows(MaxBufferSize, 50000);

        public IBulkCipherInstance GetCipherKey(BulkCipherType cipher)
        {
            int keySize, nonceSize, overhead;
            var type = GetCipherType(cipher, out keySize, out nonceSize, out overhead);
            if (type != IntPtr.Zero)
            {
                return new AeadBulkCipherInstance(type, _bufferPool, nonceSize, keySize, overhead);
            }
            return null;
        }

        private static IntPtr GetCipherType(BulkCipherType cipherType, out int keySize, out int nonceSize, out int overhead)
        {
            switch (cipherType)
            {
                case BulkCipherType.AES_128_GCM:
                    keySize = 16;
                    nonceSize = 12;
                    overhead = 16;
                    return EVP_aes_128_gcm;
                case BulkCipherType.AES_256_GCM:
                    keySize = 32;
                    nonceSize = 12;
                    overhead = 16;
                    return EVP_aes_256_gcm;
                case BulkCipherType.CHACHA20_POLY1305:
                    keySize = 32;
                    nonceSize = 12;
                    overhead = 16;
                    return EVP_chacha20_poly1305;
                default:
                    keySize = 0;
                    nonceSize = 0;
                    overhead = 0;
                    return IntPtr.Zero;
            }
        }

        public void Dispose()
        {
            _bufferPool.Dispose();
            GC.SuppressFinalize(this);
        }

        ~BulkCipherProvider()
        {
            Dispose();
        }
    }
}
