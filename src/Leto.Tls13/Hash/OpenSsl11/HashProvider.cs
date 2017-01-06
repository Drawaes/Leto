using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static Interop.LibCrypto;

namespace Leto.Tls13.Hash.OpenSsl11
{
    public class HashProvider:IHashProvider
    {
        public IHashInstance GetHashInstance(HashType hashType)
        {
            IntPtr type;
            int size;
            switch (hashType)
            {
                case HashType.SHA256:
                    type = EVP_sha256;
                    size = 256 / 8;
                    break;
                case HashType.SHA384:
                    type = EVP_sha384;
                    size = 384 / 8;
                    break;
                case HashType.SHA512:
                    type = EVP_sha512;
                    size = 512 / 8;
                    break;
                default:
                    throw new InvalidOperationException();
            }
            var ctx = EVP_MD_CTX_new();
            ThrowOnError(EVP_DigestInit_ex(ctx, type, IntPtr.Zero));
            return new HashInstance(ctx, size, hashType);
        }
    }
}
