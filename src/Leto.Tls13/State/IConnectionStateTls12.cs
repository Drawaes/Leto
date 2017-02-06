using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Leto.Tls13.State
{
    public interface IConnectionStateTls12 : IConnectionState
    {
        Span<byte> ClientRandom { get; }
        Span<byte> ServerRandom { get; }
    }
}
