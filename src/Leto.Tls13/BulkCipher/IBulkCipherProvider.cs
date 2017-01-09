using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Leto.Tls13.BulkCipher
{
    public interface IBulkCipherProvider
    {
        IBulkCipherInstance GetCipherKey(BulkCipherType cipher);
        void Dispose();
    }
}
