using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;

namespace Leto.Tls13.KeyExchange
{
    public interface IKeyShareInstance:IDisposable
    {
        bool HasPeerKey { get; }
        void SetPeerKey(ReadableBuffer peerKey);
        int KeyExchangeSize { get;}
        void WritePublicKey(ref WritableBuffer keyBuffer);
        NamedGroup  NamedGroup { get;}
        byte[] DeriveSecret();
    }
}
