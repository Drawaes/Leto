using System.IO.Pipelines;

namespace Leto.Hashes
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
