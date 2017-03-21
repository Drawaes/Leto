using System;
using System.Buffers;

namespace Leto.BulkCiphers
{
    public interface IBulkCipherKeyProvider : IDisposable
    {
        AeadBulkCipher GetCipher(BulkCipherType cipherType, Buffer<byte> keyStorage);
        (int keySize, int ivSize) GetCipherSize(BulkCipherType cipherType);
    }
}
