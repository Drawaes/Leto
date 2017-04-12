using System.Runtime.InteropServices;

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