using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Leto.Tls13.Hash
{
    public interface IHashProvider
    {
        IHashInstance GetHashInstance(HashType hashType);
        unsafe void HmacData(HashType hashType, void* key, int keyLength, void* message, int messageLength, void* result, int resultLength);
        int HashSize(HashType hashType);
        void Dispose();
    }
}
