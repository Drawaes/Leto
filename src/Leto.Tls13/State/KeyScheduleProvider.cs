using System;
using System.Buffers;
using System.Buffers.Pools;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.Internal;

namespace Leto.Tls13.State
{
    public sealed class KeyScheduleProvider:IDisposable
    {
        private const int MaxHashSize = 64;
        private const int StateSize = MaxHashSize * 6;
        private const int MaxConnections = 10000;
        private EphemeralBufferPoolWindows _bufferPool = new EphemeralBufferPoolWindows(StateSize, MaxConnections);

        public BufferPool BufferPool => _bufferPool;

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
