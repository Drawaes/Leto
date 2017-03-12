using System;

namespace Leto.BulkCiphers
{
    public interface IBulkCipherKeyProvider : IDisposable
    {
        AeadBulkCipher GetCipher(BulkCipherType cipherType);
    }
}
