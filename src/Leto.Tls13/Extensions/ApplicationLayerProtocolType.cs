using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Leto.Tls13.Extensions
{
    public enum ApplicationLayerProtocolType
    {
        None = 0,
        Http1_1,
        Spdy1,
        Spdy2,
        Spdy3,
        Turn,
        Stun,
        Http2_Tls,
        Http2_Tcp,
        WebRtc,
        Confidential_WebRtc,
        Ftp
    }
}
