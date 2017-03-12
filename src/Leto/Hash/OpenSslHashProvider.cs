using Leto.Internal;
using System;
using static Leto.Interop.LibCrypto;

namespace Leto.Hash
{
    public class OpenSslHashProvider : IHashProvider
    {
        public void HmacData(HashType hashType, Span<byte> key, Span<byte> message, Span<byte> result)
        {
            var (type, size) = GetHashType(hashType);
            HMAC(type, key, message, result);
        }

        public int HashSize(HashType hashType)
        {
            var (type, size) = GetHashType(hashType);
            return size;
        }

        private static (EVP_HashType hash, int size) GetHashType(HashType hashType)
        {
            EVP_HashType type;
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
            return (type, size);
        }

        public IHash GetHash(HashType hashType)
        {
            var (type, size) = GetHashType(hashType);
            return new OpenSslHash(type, size, hashType);
        }
    }
}
