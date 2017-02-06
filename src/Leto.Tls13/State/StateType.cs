using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Leto.Tls13.State
{
    public enum StateType
    {
        None,
        WaitHelloRetry,
        WaitClientFinished,
        SendServerHello,
        SendServerFinished,
        ServerAuthentication,
        SendClientHello,
        HandshakeComplete,
        WaitServerHello,
        WaitEncryptedExtensions,
        WaitServerVerification,
        WaitServerFinished,
        WaitEarlyDataFinished,
        WaitClientKeyExchange,
        ChangeCipherSpec
    }
}
