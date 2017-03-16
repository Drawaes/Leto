using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.Handshake.Extensions
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
