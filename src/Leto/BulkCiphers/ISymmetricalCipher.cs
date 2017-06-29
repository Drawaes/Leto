using System;
using System.Buffers;

namespace Leto.BulkCiphers
{
    public interface ISymmetricalCipher : IDisposable
    {
        Buffer<byte> IV { get; }
        int TagSize { get; }
        void Init(KeyMode mode);
        int Update(Span<byte> input, Span<byte> output);
        int Update(Span<byte> inputAndOutput);
        int Finish(Span<byte> inputAndOutput);
        int Finish(Span<byte> input, Span<byte> output);
        void AddAdditionalInfo(ref AdditionalInfo addInfo);
        void GetTag(Span<byte> span);
        void SetTag(ReadOnlySpan<byte> tagSpan);
    }
}
