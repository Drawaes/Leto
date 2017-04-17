using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.BulkCiphers
{
    public interface IKeyPair
    {
        AeadBulkCipher WriteKey { get; }
        AeadBulkCipher ReadKey { get; }
    }
}
