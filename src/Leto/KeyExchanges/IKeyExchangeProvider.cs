using Leto.Certificates;
using System;
using Leto.Internal;

namespace Leto.KeyExchanges
{
    public interface IKeyExchangeProvider : IDisposable
    {
        IKeyExchange GetKeyExchange(NamedGroup namedGroup);
        IKeyExchange GetKeyExchange(KeyExchangeType keyExchange, BigEndianAdvancingSpan supportedGroups);
        IKeyExchange GetKeyExchange(BigEndianAdvancingSpan keyshare);
        IKeyExchange GetKeyExchangeFromSupportedGroups(BigEndianAdvancingSpan buffer);
        void SetSupportedNamedGroups(params NamedGroup[] namedGroups);
    }
}
