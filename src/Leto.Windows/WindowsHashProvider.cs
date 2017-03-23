using Leto.Hashes;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Text;
using static Leto.Windows.Interop.BCrypt;

namespace Leto.Windows
{
    public class WindowsHashProvider : IHashProvider
    {
        private SafeBCryptAlgorithmHandle _sha256;
        private SafeBCryptAlgorithmHandle _sha384;
        private SafeBCryptAlgorithmHandle _sha512;

        public WindowsHashProvider()
        {
            _sha256 = BCryptOpenAlgorithmProvider(HashType.SHA256.ToString());
            _sha384 = BCryptOpenAlgorithmProvider(HashType.SHA384.ToString());
            _sha512 = BCryptOpenAlgorithmProvider(HashType.SHA512.ToString());
        }

        public IHash GetHash(HashType hashType)
        {
            throw new NotImplementedException();
        }

        public int HashSize(HashType hashType) => GetHashType(hashType).size;

        public void HmacData(HashType hashType, ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> result)
        {
            var handle = GetHashType(hashType).handle;
            BCryptHash(handle, key, message, result);
        }
        
        private (SafeBCryptAlgorithmHandle handle, int size) GetHashType(HashType hashType)
        {
            switch (hashType)
            {
                case HashType.SHA256:
                    return (_sha256, 256 / 8);
                case HashType.SHA384:
                    return (_sha384, 384 / 8);
                case HashType.SHA512:
                    return (_sha512, 512 / 8);
                default:
                    ExceptionHelper.ThrowException(new InvalidOperationException());
                    return (default(SafeBCryptAlgorithmHandle), default(int));
            }
        }
    }
}
