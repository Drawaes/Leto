using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static Interop.BCrypt;
using Microsoft.Win32.SafeHandles;
using Leto.Tls13.Internal;

namespace Leto.Tls13.Hash.Windows
{
    public class HashProvider : IHashProvider
    {
        private Tuple<SafeBCryptAlgorithmHandle, SafeBCryptAlgorithmHandle> _sha256;
        private Tuple<SafeBCryptAlgorithmHandle, SafeBCryptAlgorithmHandle> _sha384;
        private Tuple<SafeBCryptAlgorithmHandle, SafeBCryptAlgorithmHandle> _sha512;

        public HashProvider()
        {
            _sha256 = GetProviders(HashType.SHA256);
            _sha384 = GetProviders(HashType.SHA384);
            _sha512 = GetProviders(HashType.SHA512);
        }

        private Tuple<SafeBCryptAlgorithmHandle, SafeBCryptAlgorithmHandle> GetProviders(HashType hashType)
        {
            SafeBCryptAlgorithmHandle hash, hmac;
            var hashId = hashType.ToString().ToUpper();
            BCryptOpenAlgorithmProvider(out hash, hashId, null, BCryptOpenAlgorithmProviderFlags.None);
            BCryptOpenAlgorithmProvider(out hmac, hashId, null, BCryptOpenAlgorithmProviderFlags.BCRYPT_ALG_HANDLE_HMAC_FLAG);
            return Tuple.Create(hash, hmac);
        }

        public IHashInstance GetHashInstance(HashType hashType)
        {
            int size = HashSize(hashType);
            SafeBCryptAlgorithmHandle algo = null;
            switch (hashType)
            {
                case HashType.SHA256:
                    algo = _sha256.Item1;
                    break;
                case HashType.SHA384:
                    algo = _sha384.Item1;
                    break;
                case HashType.SHA512:
                    algo = _sha512.Item1;
                    break;
                default:
                    ExceptionHelper.ThrowException(new ArgumentOutOfRangeException(nameof(hashType)));
                    break;
            }
            return new HashInstance(size, algo);
        }

        public int HashSize(HashType hashType)
        {
            int size = 0;
            switch (hashType)
            {
                case HashType.SHA256:
                    size = 32;
                    break;
                case HashType.SHA384:
                    size = 48;
                    break;
                case HashType.SHA512:
                    size = 64;
                    break;
                default:
                    ExceptionHelper.ThrowException(new ArgumentOutOfRangeException(nameof(hashType)));
                    break;
            }
            return size;
        }

        public unsafe void HmacData(HashType hashType, void* key, int keyLength, void* message, int messageLength, void* result, int resultLength)
        {
            SafeBCryptAlgorithmHandle algo;
            switch (hashType)
            {
                case HashType.SHA256:
                    algo = _sha256.Item2;
                    break;
                case HashType.SHA384:
                    algo = _sha384.Item2;
                    break;
                case HashType.SHA512:
                    algo = _sha512.Item2;
                    break;
                default:
                    return;
            }
            Interop.Windows.ExceptionHelper.CheckReturnCode(BCryptHash(algo, key, keyLength, message, messageLength, result, resultLength));
        }

        public void Dispose()
        {
            _sha256?.Item1?.Dispose();
            _sha256?.Item2?.Dispose();
            _sha384?.Item1?.Dispose();
            _sha384?.Item2?.Dispose();
            _sha512?.Item1?.Dispose();
            _sha512?.Item2?.Dispose();
            GC.SuppressFinalize(this);
        }

        ~HashProvider()
        {
            Dispose();
        }
    }
}
