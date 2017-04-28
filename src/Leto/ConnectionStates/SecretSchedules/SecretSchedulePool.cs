using Leto.Internal;
using System;
using System.Buffers;
using System.Buffers.Pools;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.ConnectionStates.SecretSchedules
{
    public class SecretSchedulePool : IDisposable
    {
        const int MaxHashSize = 64;
        const int MaxKeySize = 32 + 12;
        const int Session_MaxHashBlocks = 6;
        const int Session_MaxKeys = 2;
        const int MaxInflightSessions = 200;
        public const int MaxInflightConnections = 500;
        const int Session_Size = MaxHashSize * Session_MaxHashBlocks;

        private BufferPool _ephemeralSessionPool;
        private BufferPool _ephemeralKeysPool;

        public SecretSchedulePool()
        {
            _ephemeralSessionPool = EphemeralBuffers.EphemeralBufferPool.CreateBufferPool(Session_Size, MaxInflightSessions);
            _ephemeralKeysPool = EphemeralBuffers.EphemeralBufferPool.CreateBufferPool(MaxKeySize, MaxInflightConnections * 2);
        }

        public OwnedBuffer<byte> GetSecretBuffer()
        {
            var session = _ephemeralSessionPool.Rent(Session_Size);
            return session;
        }

        public OwnedBuffer<byte> GetKeyBuffer()
        {
            var key = _ephemeralKeysPool.Rent(MaxKeySize);
            return key;
        }

        public void Dispose()
        {
            _ephemeralKeysPool?.Dispose();
            _ephemeralKeysPool = null;
            _ephemeralSessionPool?.Dispose();
            _ephemeralSessionPool = null;
            GC.SuppressFinalize(this);
        }

        ~SecretSchedulePool()
        {
            Dispose();
        }
    }
}
