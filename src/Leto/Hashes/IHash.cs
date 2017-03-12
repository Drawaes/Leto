using System;

namespace Leto.Hashes
{
    public interface IHash : IDisposable
    {
        int HashSize { get; }
        HashType HashType { get; }
        int InterimHash(Span<byte> output);
        void HashData(ReadOnlySpan<byte> data);
        int FinishHash(Span<byte> output);
    }
}
