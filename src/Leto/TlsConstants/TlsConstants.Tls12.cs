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

            public const int RandomLength = 32;
            //https://tlswg.github.io/tls13-spec/#rfc.section.4.1.3
            //Last 8 bytes of random are a special value to protect against downgrade attacks
            public static byte[] EndOfRandomDowngradeProtection { get; } = { 0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01 };
        }
    }
}
