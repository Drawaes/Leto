using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.Handshake
{
    //https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
    public enum ExtensionType : ushort
    {
        server_name = 0,
        supported_groups = 10,
        signature_algorithms = 13,
        key_share = 40,
        pre_shared_key = 41,
        early_data = 42,
        ticket_early_data_info = 46,
        supported_versions = 43,
        cookie = 44,
        psk_key_exchange_modes = 45,
        certificate_authorities = 47,
        oid_filters = 48,
        application_layer_protocol_negotiation = 16,
        SessionTicket = 35,
        renegotiation_info = 65281,
    }
}
