using Leto.Internal;
using System;
using System.Buffers;
using System.Buffers.Pools;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.ConnectionStates.SecretSchedules
{
    public class SecretSchedulePool
    {
        const int MaxHashSize = 64;
        const int MaxKeySize = 32 + 12;
        const int Session_MaxHashBlocks = 6;
        const int Session_MaxKeys = 2;
        const int MaxInflightSessions = 10000;
        const int MaxInflightConnections = 50000;
        const int Session_Size = MaxHashSize * Session_MaxHashBlocks;

        private BufferPool _ephemeralSessionPool;
        private BufferPool _ephemeralKeysPool;

        public SecretSchedulePool()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                _ephemeralSessionPool = new EphemeralBufferPoolUnix(Session_Size, MaxInflightSessions);
                _ephemeralKeysPool = new EphemeralBufferPoolUnix(MaxKeySize * 2, MaxInflightConnections);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                _ephemeralSessionPool = new EphemeralBufferPoolWindows(Session_Size, MaxInflightSessions);
                _ephemeralKeysPool = new EphemeralBufferPoolWindows(MaxKeySize * 2, MaxInflightConnections);
            }
            else
            {
                ExceptionHelper.ThrowException(new NotImplementedException("Unknown OS for ephemeral buffer pool"));
            }
        }

        public (OwnedBuffer<byte> session, OwnedBuffer<byte> keys) GetSecretBuffer()
        {
            var session = _ephemeralSessionPool.Rent(Session_Size);
            var keys = _ephemeralKeysPool.Rent(MaxKeySize * 2);
            return (session, keys);
        }
    }
}
