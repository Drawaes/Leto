using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.BulkCipher;
using Leto.Tls13.Hash;

namespace Leto.Tls13
{
    public class CipherSuite
    {
        public HashType HashType { get; set; }
        public BulkCipherType BulkCipherType { get; set; }
        public ushort CipherCode { get; set; }
    }
}
