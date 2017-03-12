using System;

namespace Leto.BulkCiphers
{
    public interface IBulkCipherKey : IDisposable
    {
        Memory<byte> Key { get; }
        Memory<byte> IV { get; }
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
