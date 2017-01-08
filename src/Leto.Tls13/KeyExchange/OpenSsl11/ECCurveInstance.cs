using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using static Interop.LibCrypto;

namespace Leto.Tls13.KeyExchange.OpenSsl11
{
    public class ECCurveInstance : IKeyShareInstance
    {
        private bool _hasPeerKey;
        private int _keyExchangeSize;
        private NamedGroup _namedGroup;
        private int _curveNid;

        public ECCurveInstance(NamedGroup namedGroup)
        {
            _namedGroup = namedGroup;
            switch(namedGroup)
            {
                case NamedGroup.secp256r1:
                    _curveNid = OBJ_sn2nid("prime256v1");
                    break;
                case NamedGroup.secp384r1:
                    _curveNid = OBJ_sn2nid("secp384r1");
                    break;
                case NamedGroup.secp521r1:
                    _curveNid = OBJ_sn2nid("secp521r1");
                    break;
            }
        }

        public bool HasPeerKey => _hasPeerKey;
        public int KeyExchangeSize => _keyExchangeSize;
        public NamedGroup NamedGroup => _namedGroup;

        public byte[] DeriveSecret()
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }

        public void SetPeerKey(ReadableBuffer peerKey)
        {
            throw new NotImplementedException();
        }
        
        public void WritePublicKey(ref WritableBuffer keyBuffer)
        {
            throw new NotImplementedException();
        }
    }
}
