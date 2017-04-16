using System;
using System.Buffers;

namespace Leto.BulkCiphers
{
    public interface IBulkCipherKeyProvider : IDisposable
    {
        T GetCipher<T>(BulkCipherType cipherType, OwnedBuffer<byte> keyStorage) where T : AeadBulkCipher, new();
        (int keySize, int ivSize) GetCipherSize(BulkCipherType cipherType);
    }
}