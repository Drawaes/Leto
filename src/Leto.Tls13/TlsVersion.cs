using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Leto.Tls13
{
    public enum TlsVersion:ushort
    {
        Tls1 = 0x0301,
        Tls11 = 0x0302,
        Tls12 = 0x0303,
        Tls13Draft18 = 0x7f12
    }
}
