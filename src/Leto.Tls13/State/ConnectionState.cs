using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.BulkCipher;
using Leto.Tls13.Hash;
using Leto.Tls13.KeyExchange;

namespace Leto.Tls13.State
{
    public class ConnectionState
    {
        public ConnectionState(CryptoProvider provider)
        {
            CryptoProvider = provider;
        }

        public IKeyShareInstance KeyShare { get; set; }
        public IHashInstance HandshakeHash { get; set; }
        public CryptoProvider CryptoProvider { get; set; }
        public IBulkCipherInstance ReadKey { get; set; }
        public IBulkCipherInstance WriteKey { get; set; }
        public CipherSuite CipherSuite { get; internal set; }
        public StateType State { get; internal set; }

        internal void StartHandshakeHash(ReadableBuffer readable)
        {
            HandshakeHash = CryptoProvider.HashProvider.GetHashInstance(CipherSuite.HashType);
            HandshakeHash.HashData(readable);
        }
    }
}
