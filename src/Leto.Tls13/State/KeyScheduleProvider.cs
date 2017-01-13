using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.Internal;

namespace Leto.Tls13.State
{
    public class KeyScheduleProvider:IDisposable
    {
        private const int MaxHashSize = 64;
        private const int StateSize = MaxHashSize * 6;
        private const int MaxConnections = 10000;
        private SecureBufferPool _bufferPool = new SecureBufferPool(StateSize, MaxConnections);

        public KeySchedule GetKeySchedule(IConnectionState state, byte[] resumptionSecret)
        {
            return new KeySchedule(state, _bufferPool, resumptionSecret);
        }

        public void Dispose()
        {
            _bufferPool.Dispose();
            _bufferPool = null;
            GC.SuppressFinalize(this);
        }

        ~KeyScheduleProvider()
        {
            Dispose();
        }
    }
}
