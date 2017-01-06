using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Leto.Tls13.Hash
{
    public interface IHashProvider
    {
        IHashInstance GetHashInstance(HashType hashType);
    }
}
