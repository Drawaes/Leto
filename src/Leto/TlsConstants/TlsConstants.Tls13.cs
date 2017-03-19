using System.Linq;
using System.Text;

namespace Leto
{
    public static partial class TlsConstants
    {
        public static partial class Tls13
        {
            public const string Prefix = "TLS 1.3, ";

            public static readonly byte[] Label_ServerCertificateVerify = Encoding.ASCII.GetBytes(Prefix + "server CertificateVerify\0");
            public static readonly byte[] Label_ClientHandshakeTrafficSecret = Encoding.ASCII.GetBytes(Prefix + "client handshake traffic secret");
            public static readonly byte[] Label_ServerHandshakeTrafficSecret = Encoding.ASCII.GetBytes(Prefix + "server handshake traffic secret");
            public static readonly byte[] Label_ClientApplicationTrafficSecret = Encoding.ASCII.GetBytes(Prefix + "client application traffic secret");
            public static readonly byte[] Label_ServerApplicationTrafficSecret = Encoding.ASCII.GetBytes(Prefix + "server application traffic secret");
            public static readonly byte[] Label_ClientEarlyTrafficSecret = Encoding.ASCII.GetBytes(Prefix + "client early traffic secret");
            public static readonly byte[] Label_ResumptionSecret = Encoding.ASCII.GetBytes(Prefix + "resumption master secret");
            public static readonly byte[] Label_ServerFinishedKey = Encoding.ASCII.GetBytes(Prefix + "finished");
            public static readonly byte[] Label_TrafficKey = Encoding.ASCII.GetBytes(Prefix + "key");
            public static readonly byte[] Label_TrafficIv = Encoding.ASCII.GetBytes(Prefix + "iv");
            public static readonly byte[] SignatureDigestPrefix = Enumerable.Repeat((byte)0x20, 64).ToArray();
        }
    }
}
