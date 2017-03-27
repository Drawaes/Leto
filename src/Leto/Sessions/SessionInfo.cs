using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.Sessions
{
    internal unsafe struct SessionInfo
    {
        public TlsVersion Version;
        public ushort CipherSuite;
        public uint Timestamp;
    }
}
