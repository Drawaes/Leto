using System;
using System.Buffers;

namespace Leto.BulkCiphers
{
    public interface IBulkCipherKey : IDisposable
    {
        Buffer<byte> Key { get; }
        Buffer<byte> IV { get; }
        int TagSize { get; }
        void Init(KeyMode mode);
        int Update(Span<byte> input, Span<byte> output);
        int Update(Span<byte> inputAndOutput);
        void AddAdditionalInfo(AdditionalInfo addInfo);
        void ReadTag(Span<byte> span);
        void WriteTag(ReadOnlySpan<byte> tagSpan);
        void Finish();
    }
}
