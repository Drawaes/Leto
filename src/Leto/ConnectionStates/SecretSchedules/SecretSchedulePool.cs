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
        const int MaxSessions = 10000;
        const int Session_Size = (Session_MaxKeys * MaxKeySize) + (MaxHashSize * Session_MaxHashBlocks);

        private BufferPool _ephemeralPool;

        public SecretSchedulePool()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                _ephemeralPool = new EphemeralBufferPoolUnix(Session_Size, MaxSessions);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                _ephemeralPool = new EphemeralBufferPoolWindows(Session_Size, MaxSessions);
            }
            else
            {
                ExceptionHelper.ThrowException(new NotImplementedException("Unknown OS for ephemeral buffer pool"));
            }
        }

        public OwnedMemory<byte> GetSecretBuffer()
        {
            return _ephemeralPool.Rent(Session_Size);
        }
    }
}
