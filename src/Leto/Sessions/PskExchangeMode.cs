using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.Sessions
{
    [Flags]
    public enum PskExchangeMode : byte
    {
        psk_ke = 0,
        psk_dhe_ke = 1,
        none = 255
    }
}
