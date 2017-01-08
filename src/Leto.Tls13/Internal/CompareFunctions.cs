using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Leto.Tls13.Internal
{
    public class CompareFunctions
    {
        //Has no branching, will always take the same about of time for 
        //the same length values, as we are comparing hashes and the algo
        //is public there is no information to be gained from this
        public static bool ConstantTimeEquals(Span<byte> a, Span<byte> b)
        {
            uint diff = (uint)a.Length ^ (uint)b.Length;
            for (int i = 0; i < a.Length && i < b.Length; i++)
                diff |= (uint)(a[i] ^ b[i]);
            return diff == 0;
        }
    }
}
