using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Leto.Tls13.RecordLayer
{
    public enum RecordType : byte
    {
        ChangeCipherSpec = 0x14,
        Alert = 0x15,
        Handshake = 0x16,
        Application = 0x17,
    }
}
