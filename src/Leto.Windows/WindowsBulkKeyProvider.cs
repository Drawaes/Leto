using Leto.BulkCiphers;
using Microsoft.Win32.SafeHandles;
using System;
using System.Buffers;
using System.Collections.Generic;
using static Leto.Windows.Interop.BCrypt;

namespace Leto.Windows
{
    public sealed class WindowsBulkKeyProvider : IBulkCipherKeyProvider
    {
        private SafeBCryptAlgorithmHandle _aesHandle;

        public WindowsBulkKeyProvider()
        {
            _aesHandle = BCryptOpenAlgorithmProvider("AES");
        }

        private (int keySize, int ivSize, string chainingMode) GetCipher(BulkCipherType cipherType)
        {
            switch (cipherType)
            {
                case BulkCipherType.AES_128_GCM:
                    return (16, 12, BCRYPT_CHAIN_MODE_GCM);
                case BulkCipherType.AES_256_GCM:
                    return (32, 12, BCRYPT_CHAIN_MODE_GCM);
                default:
                    throw new NotImplementedException();
            }
        }

        public AeadBulkCipher GetCipher(BulkCipherType cipherType, Buffer<byte> keyStorage)
        {
            var (keySize, ivSize, chainingMode) = GetCipher(cipherType);
            var key = new WindowsBulkCipherKey(_aesHandle, keyStorage, keySize, ivSize, 16, chainingMode);
            return new AeadBulkCipher(key);
        }

        public (int keySize, int ivSize) GetCipherSize(BulkCipherType cipherType)
        {
            var (keySize, ivSize, cipher) = GetCipher(cipherType);
            return (keySize, ivSize);
        }

        public void Dispose()
        {
            GC.SuppressFinalize(this);
        }

        ~WindowsBulkKeyProvider()
        {
            Dispose();
        }
    }
}
