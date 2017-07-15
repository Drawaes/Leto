using System;
using System.Collections.Generic;
using System.Text;

namespace Leto
{
    public class SecurePipeListenerConfig
    {
        public int MaxInFightHandshakes { get; set; } = 200;
        public int MaxInFlightConnections { get; set; } = 300;
    }
}
