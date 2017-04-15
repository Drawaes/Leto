using Leto.BulkCiphers;
using Leto.Internal;
using Microsoft.Win32.SafeHandles;
using System;
using System.Buffers;
using System.Collections.Generic;
using static Leto.Windows.Interop.BCrypt;

namespace Leto.Windows
{
    public sealed class WindowsBulkKeyProvider : IBulkCipherKeyProvider
    {
        private SafeBCryptAlgorithmHandle _aesGcmHandle;
        private BufferPool _keyScratchSpace;
        //This is used for inflight calls, we have TempIV (12), MacContext(16), Tag (16), Authdata
        private static int _maxTagSize = 16;
        private static int _blockSize = 16;
        private static readonly unsafe int _scratchSpaceSize = sizeof(AdditionalInfo) + _maxTagSize + _blockSize * 2  + sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO);
        
        public WindowsBulkKeyProvider()
        {
            _aesGcmHandle = BCryptOpenAlgorithmProvider("AES");
            SetBlockChainingMode(_aesGcmHandle, BCRYPT_CHAIN_MODE_GCM);
            //This param should be somewhere better and configured, but for now we will link it to one common place
            _keyScratchSpace = new EphemeralBufferPoolWindows(_scratchSpaceSize, ConnectionStates.SecretSchedules.SecretSchedulePool.MaxInflightConnections * 2);
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

        public T GetCipher<T>(BulkCipherType cipherType, Buffer<byte> keyStorage) where T : AeadBulkCipher, new()
        {
            var (keySize, ivSize, chainingMode) = GetCipher(cipherType);
            var key = new WindowsBulkCipherKey(_aesGcmHandle, keyStorage, keySize, ivSize, 16, chainingMode, _keyScratchSpace.Rent(_scratchSpaceSize));
            var returnValue = new T();
            returnValue.SetKey(key);
            return returnValue;
        }

        public (int keySize, int ivSize) GetCipherSize(BulkCipherType cipherType)
        {
            var (keySize, ivSize, cipher) = GetCipher(cipherType);
            return (keySize, ivSize);
        }

        public void Dispose()
        {
            try
            {
                _keyScratchSpace?.Dispose();
                _keyScratchSpace = null;
            }
            catch
            {
                //Nom Nom
            }
            GC.SuppressFinalize(this);
        }

        ~WindowsBulkKeyProvider()
        {
            Dispose();
        }
    }
}
