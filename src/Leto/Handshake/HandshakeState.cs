using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.Handshake
{
    public enum HandshakeState
    {
        WaitingForClientKeyExchange,
        WaitingForChangeCipherSpec,
        WaitingForClientFinished
    }
}
