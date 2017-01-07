using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Leto.Tls13.Handshake
{
    public enum ExtensionType : ushort
    {
        supported_groups = 10,
        signature_algorithms = 13,
        key_share = 40,
        pre_shared_key = 41,
        early_data = 42,
        supported_versions = 43,
        cookie = 44,
        psk_key_exchange_modes = 45,
        certificate_authorities = 47,
        oid_filters = 48,
        application_layer_protocol_negotiation = 16
    }
}
