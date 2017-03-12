using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;

namespace Leto.Hash
{
    public static class HashExtensions
    {
        public static void HashData(this IHash hash, ReadableBuffer dataToHash)
        {
            foreach (var m in dataToHash)
            {
                hash.HashData(m.Span);
            }
        }
    }
}
