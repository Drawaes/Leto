using Leto.Certificates;
using System;

namespace Leto.Keyshares
{
    public interface IKeyshareProvider : IDisposable
    {
        IKeyshare GetKeyshare(NamedGroup namedGroup);
        IKeyshare GetKeyshare(KeyExchangeType keyExchange, Span<byte> supportedGroups);
    }
}
