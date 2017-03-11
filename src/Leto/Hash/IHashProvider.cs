using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.Hash
{
    public interface IHashProvider
    {
        void HmacData(HashType hashType, Span<byte> key, Span<byte> message, Span<byte> result);
        int HashSize(HashType hashType);
    }
}
