using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.Hash
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
