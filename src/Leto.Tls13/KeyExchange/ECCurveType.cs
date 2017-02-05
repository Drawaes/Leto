using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Leto.Tls13.KeyExchange
{
    public enum ECCurveType:byte
    {
        explicit_prime =1,
        explicit_char2 =2,
        named_curve =3,
    }
}