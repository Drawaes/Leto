using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Leto.Tls13.Handshake
{
    public enum HandshakeType : byte
    {
        client_hello = 1,
        server_hello = 2,
        new_session_ticket = 4,
        end_of_early_data = 5,
        hello_retry_request = 6,
        encrypted_extensions = 8,
        certificate = 11,
        server_key_exchange = 12,
        certificate_request = 13,
        certificate_verify = 15,
        finished = 20,
        key_update = 24,
    }
}
