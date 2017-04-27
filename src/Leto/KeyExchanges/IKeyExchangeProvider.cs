using Leto.Certificates;
using System;
using Leto.Internal;

namespace Leto.KeyExchanges
{
    public interface IKeyExchangeProvider : IDisposable
    {
        IKeyExchange GetKeyExchange(KeyExchangeType keyExchange, BigEndianAdvancingSpan supportedGroups);
        void SetSupportedNamedGroups(params NamedGroup[] namedGroups);
    }
}
