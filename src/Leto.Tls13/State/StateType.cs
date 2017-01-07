using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Leto.Tls13.State
{
    public enum StateType
    {
        None,
        SendHelloRetry,
        WaitHelloRetry,
        SendServerFlightOne,
        WaitClientFlightOne,
        SendServerHello,
        SendServerCertificate
    }
}
