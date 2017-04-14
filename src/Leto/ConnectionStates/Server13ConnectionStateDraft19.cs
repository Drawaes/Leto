using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.ConnectionStates
{
    public sealed class Server13ConnectionStateDraft19:Server13ConnectionState<SecretSchedules.SecretSchedule13Draft19>
    {
        public Server13ConnectionStateDraft19(SecurePipeConnection connection):base(connection)
        {
            _protocolVersion = TlsVersion.Tls13Draft19;
        }
    }
}
