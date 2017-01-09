using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Leto.Tls13.Hash
{
    public interface IHashProvider
    {
        IHashInstance GetHashInstance(HashType hashType);
        unsafe void HmacData(HashType hashType, byte* key, int keyLength, byte* message, int messageLength, byte* result, int resultLength);
        int HashSize(HashType hashType);
        void Dispose();
    }
}
