using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.ConnectionStates
{
    public sealed class Server13ConnectionStateDraft18: Server13ConnectionState<SecretSchedules.SecretSchedule13>
    {
        public Server13ConnectionStateDraft18(SecurePipeConnection connection):base(connection)
        {
            _protocolVersion = TlsVersion.Tls13Draft18;
        }
    }
}
