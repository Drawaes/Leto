using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Leto.Tls13.BulkCipher
{
    public enum BulkCipherType
    {
        AES_128_GCM,
        AES_256_GCM,
        CHACHA20_POLY1305,
        AES_128_CCM,
        AES_128_CCM_8,
    }
}
