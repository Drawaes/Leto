using Leto.Interop;
using System;
using System.Buffers.Pools;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.BulkCipher
{
    public class OpenSslBulkKeyProvider
    {
        private static readonly int s_maxKeyIVSize = 32 + 12;
        private static readonly int s_maxSessions = 10000;
        private BufferPool _ephemeralPool;

        public OpenSslBulkKeyProvider()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                _ephemeralPool = new Internal.EphemeralBufferPoolUnix(s_maxKeyIVSize, s_maxSessions);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                _ephemeralPool = new Internal.EphemeralBufferPoolWindows(s_maxKeyIVSize, s_maxSessions);
            }
            else
            {
                throw new NotImplementedException("Unknown OS for ephemeral buffer pool");
            }
        }

        public AeadBulkCipher GetCipher(BulkCipherType cipherType)
        {
            OpenSslBulkKey key;
            switch (cipherType)
            {
                case BulkCipherType.AES_128_GCM:
                    key = new OpenSslBulkKey(LibCrypto.EVP_aes_128_gcm, _ephemeralPool, 16, 12, 16);
                    break;
                case BulkCipherType.AES_256_GCM:
                    key = new OpenSslBulkKey(LibCrypto.EVP_aes_256_gcm, _ephemeralPool, 32, 12, 16);
                    break;
                case BulkCipherType.CHACHA20_POLY1305:
                    key = new OpenSslBulkKey(LibCrypto.EVP_chacha20_poly1305, _ephemeralPool, 32, 12, 16);
                    break;
                default:
                    throw new NotImplementedException();
            }
            return new AeadBulkCipher(key);
        }
    }
}
