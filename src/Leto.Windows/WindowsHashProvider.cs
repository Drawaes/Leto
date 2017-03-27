using Leto.Hashes;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Text;
using static Leto.Windows.Interop.BCrypt;

namespace Leto.Windows
{
    public class WindowsHashProvider : IHashProvider, IDisposable
    {
        private (SafeBCryptAlgorithmHandle hash, SafeBCryptAlgorithmHandle hmac) _sha256;
        private (SafeBCryptAlgorithmHandle hash, SafeBCryptAlgorithmHandle hmac) _sha384;
        private (SafeBCryptAlgorithmHandle hash, SafeBCryptAlgorithmHandle hmac) _sha512;

        public WindowsHashProvider()
        {
            _sha256 = BCryptOpenAlgorithmHashProvider(HashType.SHA256.ToString());
            _sha384 = BCryptOpenAlgorithmHashProvider(HashType.SHA384.ToString());
            _sha512 = BCryptOpenAlgorithmHashProvider(HashType.SHA512.ToString());
        }

        public IHash GetHash(HashType hashType)
        {
            var (handle, hmac, size) = GetHashType(hashType);
            return new WindowsHash(handle, size, hashType);
        }

        public int HashSize(HashType hashType) => GetHashType(hashType).size;

        public void HmacData(HashType hashType, ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> result)
        {
            var handle = GetHashType(hashType).hmac;
            BCryptHash(handle, key, message, result);
        }

        private (SafeBCryptAlgorithmHandle handle, SafeBCryptAlgorithmHandle hmac, int size) GetHashType(HashType hashType)
        {
            switch (hashType)
            {
                case HashType.SHA256:
                    return (_sha256.hash, _sha256.hmac, 256 / 8);
                case HashType.SHA384:
                    return (_sha384.hash, _sha384.hmac, 384 / 8);
                case HashType.SHA512:
                    return (_sha512.hash, _sha512.hmac, 512 / 8);
                default:
                    ExceptionHelper.ThrowException(new InvalidOperationException());
                    return (null, null, default(int));
            }
        }
        
        public void Dispose()
        {
            _sha256.hash.Dispose();
            _sha256.hmac.Dispose();
            _sha384.hash.Dispose();
            _sha384.hmac.Dispose();
            _sha512.hash.Dispose();
            _sha512.hmac.Dispose();
            GC.SuppressFinalize(this);
        }

        ~WindowsHashProvider()
        {
            Dispose();
        }
    }
}
