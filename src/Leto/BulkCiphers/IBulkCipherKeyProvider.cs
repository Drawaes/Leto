using System;
using System.Buffers;

namespace Leto.BulkCiphers
{
    public interface IBulkCipherKeyProvider : IDisposable
    {
        T GetCipher<T>(BulkCipherType cipherType, OwnedBuffer<byte> keyStorage) where T : AeadBulkCipher, new();
        ISymmetricalCipher GetCipherKey(BulkCipherType cipherType, OwnedBuffer<byte> keyStorag);
        (int keySize, int ivSize) GetCipherSize(BulkCipherType cipherType);
    }
}