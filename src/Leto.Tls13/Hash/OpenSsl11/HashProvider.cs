using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.Internal;
using static Interop.LibCrypto;

namespace Leto.Tls13.Hash.OpenSsl11
{
    public class HashProvider:IHashProvider
    {
        public IHashInstance GetHashInstance(HashType hashType)
        {
            int size;
            IntPtr type = GetHashType(hashType, out size);
            var ctx = EVP_MD_CTX_new();
            ThrowOnError(EVP_DigestInit_ex(ctx, type, IntPtr.Zero));
            return new HashInstance(ctx, size, hashType);
        }

        private static IntPtr GetHashType(HashType hashType, out int size)
        {
            IntPtr type;
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
            return type;
        }

        public unsafe void HmacData(HashType hashType, byte* key, int keyLength, byte* message, int messageLength, byte* result, int resultLength)
        {
            int size;
            var type = GetHashType(hashType, out size);
            HMAC(type, key, keyLength, message, messageLength, result, ref resultLength);
            if(resultLength != size)
            {
                ExceptionHelper.ThrowException(new ArgumentOutOfRangeException());
            }
        }

        public int HashSize(HashType hashType)
        {
            int size;
            GetHashType(hashType, out size);
            return size;
        }

        public void Dispose()
        {
            
        }
    }
}
