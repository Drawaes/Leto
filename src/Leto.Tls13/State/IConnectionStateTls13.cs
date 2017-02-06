using System;
using System.IO.Pipelines;
using System.Threading.Tasks;
using Leto.Tls13.BulkCipher;
using Leto.Tls13.Certificates;
using Leto.Tls13.Handshake;
using Leto.Tls13.Hash;
using Leto.Tls13.Internal;
using Leto.Tls13.KeyExchange;
using Leto.Tls13.Sessions;

namespace Leto.Tls13.State
{
    public interface IConnectionStateTls13 : IConnectionState
    {
        KeySchedule13 KeySchedule { get; set; }
        int PskIdentity { get; set; }
        PskKeyExchangeMode PskKeyExchangeMode { get; set; }
        bool EarlyDataSupported { get; set; }
    }
}