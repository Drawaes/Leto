using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;

namespace Leto.Tls13.KeyExchange.OpenSsl11
{
    public class ECCurveInstance : IKeyShareInstance
    {
        private bool _hasPeerKey;
        private int _keyExchangeSize;

        public bool HasPeerKey => _hasPeerKey;
        public int KeyExchangeSize => _keyExchangeSize;

        public void Dispose()
        {
            throw new NotImplementedException();
        }

        public void SetPeerKey(ReadableBuffer peerKey)
        {
            throw new NotImplementedException();
        }

        public void SetPeerKey(Span<byte> peerKey)
        {
            throw new NotImplementedException();
            _hasPeerKey = true;
        }

        public void WritePublicKey(ref WritableBuffer keyBuffer)
        {
            throw new NotImplementedException();
        }
    }
}
