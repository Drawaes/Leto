using Leto.Hashes;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Text;
using static Leto.Windows.Interop.BCrypt;

namespace Leto.Windows
{
    public class WindowsHash : IHash
    {
        private SafeBCryptHashHandle _hashHandle;
        private int _size;
        private HashType _hashType;

        internal WindowsHash(SafeBCryptAlgorithmHandle algoHandle, int size, HashType hashType)
        {
            _hashType = hashType;
            _size = size;
            _hashHandle = BCryptCreateHash(algoHandle);
        }

        public int HashSize => _size;
        public HashType HashType => _hashType;

        public int FinishHash(Span<byte> output)
        {
            using (_hashHandle)
            {
                BCryptFinishHash(_hashHandle, output);
            }
            _hashHandle = null;
            return _size;
        }

        public void HashData(ReadOnlySpan<byte> data)
        {
            BCryptHashData(_hashHandle, data);
        }

        public int InterimHash(Span<byte> output)
        {
            using (var newHash = BCryptDuplicateHash(_hashHandle))
            {
                BCryptFinishHash(newHash, output);
                return _size;
            }
        }

        public void Dispose()
        {
            _hashHandle?.Dispose();
            _hashHandle = null;
            GC.SuppressFinalize(this);
        }

        ~WindowsHash()
        {
            Dispose();
        }
    }
}
