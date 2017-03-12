using System;

namespace Leto.Hashes
{
    public interface IHashProvider
    {
        void HmacData(HashType hashType, ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> result);
        int HashSize(HashType hashType);
        IHash GetHash(HashType hashType);
    }
}
