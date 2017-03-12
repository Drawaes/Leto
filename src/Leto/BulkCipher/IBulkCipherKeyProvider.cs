using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.BulkCipher
{
    public interface IBulkCipherKeyProvider : IDisposable
    {
        AeadBulkCipher GetCipher(BulkCipherType cipherType);
    }
}
