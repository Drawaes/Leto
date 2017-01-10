using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using static Interop.BCrypt;
using Microsoft.Win32.SafeHandles;
using Leto.Tls13.Hash;

namespace Leto.Tls13.KeyExchange.Windows
{
    public class ECCurveInstance : IKeyshareInstance
    {
        private SafeBCryptAlgorithmHandle _algo;
        private bool _hasPeerKey;
        private NamedGroup _group;

        internal ECCurveInstance(SafeBCryptAlgorithmHandle algo, NamedGroup group)
        {
            _group = group;
            _algo = algo;
        }

        public bool HasPeerKey => _hasPeerKey;

        public int KeyExchangeSize
        {
            get
            {
                throw new NotImplementedException();
            }
        }
        public NamedGroup NamedGroup => _group;

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

        public unsafe void DeriveSecret(IHashProvider hashProvider, HashType hashType, void* salt, int saltSize, void* output, int outputSize)
        {
            throw new NotImplementedException();
        }
    }
}
