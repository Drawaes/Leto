using System;
using static Leto.Interop.LibCrypto;
using Leto.Internal;

namespace Leto.Hashes
{
    public class OpenSslHashProvider : IHashProvider
    {
        public void HmacData(HashType hashType, Span<byte> key, Span<byte> message, Span<byte> result)
        {
            var (type, size) = GetHashType(hashType);
            HMAC(type, key, message, result);
        }

        public int HashSize(HashType hashType) => GetHashType(hashType).size;

        private static (EVP_HashType hash, int size) GetHashType(HashType hashType)
        {
            switch (hashType)
            {
                case HashType.SHA256:
                    return (EVP_sha256, 256 / 8);
                case HashType.SHA384:
                    return (EVP_sha384, 384 / 8);
                case HashType.SHA512:
                    return (EVP_sha512, 512 / 8);
                default:
                    ExceptionHelper.ThrowException(new InvalidOperationException());
                    return (default(EVP_HashType), default(int));
            }
        }

        public IHash GetHash(HashType hashType)
        {
            var (type, size) = GetHashType(hashType);
            return new OpenSslHash(type, size, hashType);
        }
    }
}
