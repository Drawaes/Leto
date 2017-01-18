using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Leto.Tls13.Internal
{
    public class Tls1_3Consts
    {
        public const string Prefix = "TLS 1.3, ";

        public static readonly byte[] ServerCertificateVerify = Encoding.ASCII.GetBytes(Prefix + "server CertificateVerify\0");
        public static readonly byte[] ClientHandshakeTrafficSecret = Encoding.ASCII.GetBytes(Prefix + "client handshake traffic secret");
        public static readonly byte[] ServerHandshakeTrafficSecret = Encoding.ASCII.GetBytes(Prefix + "server handshake traffic secret");
        public static readonly byte[] ClientApplicationTrafficSecret = Encoding.ASCII.GetBytes(Prefix + "client application traffic secret");
        public static readonly byte[] ServerApplicationTrafficSecret = Encoding.ASCII.GetBytes(Prefix + "server application traffic secret");
        public static readonly byte[] ClientEarlyTrafficSecret = Encoding.ASCII.GetBytes(Prefix + "client early traffic secret");
        public static readonly byte[] ResumptionSecret = Encoding.ASCII.GetBytes(Prefix + "resumption master secret");
        public static readonly byte[] ServerFinishedKey = Encoding.ASCII.GetBytes(Prefix + "finished");
        public static readonly byte[] TrafficKey = Encoding.ASCII.GetBytes(Prefix + "key");
        public static readonly byte[] TrafficIv = Encoding.ASCII.GetBytes(Prefix + "iv");
        public static readonly byte[] SignatureDigestPrefix = Enumerable.Repeat((byte)0x20, 64).ToArray();
    }
}