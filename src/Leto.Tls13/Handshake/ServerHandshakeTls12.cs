using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.State;

namespace Leto.Tls13.Handshake
{
    public class ServerHandshakeTls12
    {
        public static WritableBuffer SendCertificates(WritableBuffer buffer, IConnectionState connectionState)
        {
            return buffer;
        }
    }
}
