using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.Keyshares
{
    public interface IKeyshareProvider:IDisposable
    {
        IKeyshare GetKeyShare(NamedGroup namedGroup);
    }
}
