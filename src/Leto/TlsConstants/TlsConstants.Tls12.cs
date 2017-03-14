using System.Text;

namespace Leto
{
    public static partial class TlsConstants
    {
        public static partial class Tls12
        {
            public static byte[] Label_KeyExpansion { get; } = Encoding.ASCII.GetBytes("key expansion");
            public static byte[] Label_MasterSecret { get; } = Encoding.ASCII.GetBytes("master secret");
            public static byte[] Label_ClientFinished { get; } = Encoding.ASCII.GetBytes("client finished");
            public static byte[] Label_ServerFinished { get; } = Encoding.ASCII.GetBytes("server finished");
        }
    }
}
