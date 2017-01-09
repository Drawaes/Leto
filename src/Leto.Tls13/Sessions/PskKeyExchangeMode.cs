using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Leto.Tls13.Sessions
{
    [Flags]
    public enum PskKeyExchangeMode:byte
    {
        psk_ke = 0,
        psk_dhe_ke = 1,
        none = 255
    }
}
