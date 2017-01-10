using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.Hash;

namespace Leto.Tls13.KeyExchange
{
    public interface IKeyshareInstance:IDisposable
    {
        bool HasPeerKey { get; }
        void SetPeerKey(ReadableBuffer peerKey);
        int KeyExchangeSize { get;}
        void WritePublicKey(ref WritableBuffer keyBuffer);
        NamedGroup  NamedGroup { get;}
        unsafe void DeriveSecret(IHashProvider hashProvider, HashType hashType, void* salt, int saltSize, void* output, int outputSize);
    }
}
