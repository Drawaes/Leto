using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Sessions
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct SessionInfo
    {
        public TlsVersion Version;
        public ushort CipherSuite;
        public long Timestamp;
    }
}