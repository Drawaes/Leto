using System.Text;

namespace Leto
{
    public static partial class TlsConstants
    {
        public static partial class Tls12
        {
            public static byte[] Label_KeyExpansion { get; } = Encoding.ASCII.GetBytes("key expansion");
        }
    }
}
