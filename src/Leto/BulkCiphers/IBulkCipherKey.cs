using System;
using System.Buffers;

namespace Leto.BulkCiphers
{
    public interface IBulkCipherKey : IDisposable
    {
        Buffer<byte> IV { get; }
        int TagSize { get; }
        void Init(KeyMode mode);
        int Update(Span<byte> input, Span<byte> output);
        int Update(Span<byte> inputAndOutput);
        void AddAdditionalInfo(ref AdditionalInfo addInfo);
        void ReadTag(Span<byte> span);
        void WriteTag(ReadOnlySpan<byte> tagSpan);
    }
}