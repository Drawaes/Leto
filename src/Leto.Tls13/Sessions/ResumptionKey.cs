using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.BulkCipher;
using static Interop.LibCrypto;

namespace Leto.Tls13.Sessions
{
    public class ResumptionKey
    {
        private long _randomId;
        private long _randomServiceId;
        private byte[] _key;
        private byte[] _nounceBase;
        private ulong[] _sequence;
        
        public ResumptionKey(long serviceId, long id, byte[] key, byte[] nounceBase)
        {
            _randomServiceId = serviceId;
            _randomId = id;
            _key = key;
            _nounceBase = nounceBase;
        }

        public byte[] DecryptSession(ReadableBuffer buffer)
        {
            throw new NotImplementedException();
        }
    }
}
