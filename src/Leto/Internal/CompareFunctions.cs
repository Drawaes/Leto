using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.Internal
{
    public static class CompareFunctions
    {
        //Has no branching, should always take the same amount of time for 
        //the same length values, as we are comparing hashes and the algo
        //is public there is no information to be gained from the length
        //being incorrect
        public static bool ConstantTimeEquals(this Span<byte> a, Span<byte> b)
        {
            var diff = (uint)a.Length ^ (uint)b.Length;
            for (var i = 0; i < a.Length && i < b.Length; i++)
            {
                diff |= (uint)(a[i] ^ b[i]);
            }
            return diff == 0;
        }
    }
}
