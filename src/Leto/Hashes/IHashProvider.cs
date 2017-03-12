using System;

namespace Leto.Hashes
{
    public interface IHashProvider
    {
        void HmacData(HashType hashType, Span<byte> key, Span<byte> message, Span<byte> result);
        int HashSize(HashType hashType);
        IHash GetHash(HashType hashType);
    }
}
