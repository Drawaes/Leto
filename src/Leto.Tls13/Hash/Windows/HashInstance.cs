using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using static Interop.BCrypt;
using Microsoft.Win32.SafeHandles;
using Leto.Tls13.Interop.Windows;

namespace Leto.Tls13.Hash.Windows
{
    public class HashInstance : IHashInstance
    {
        private int _hashSize;
        private SafeBCryptHashHandle _hash;

        internal HashInstance(int size, SafeBCryptAlgorithmHandle algo)
        {
            ExceptionHelper.CheckReturnCode(BCryptCreateHash(algo, out _hash, IntPtr.Zero, 0, null, 0, BCryptCreateHashFlags.None));
            _hashSize = size;
        }

        public int HashSize => _hashSize;

        public unsafe void HashData(byte* message, int messageLength)
        {
            ExceptionHelper.CheckReturnCode(BCryptHashData(_hash, message, messageLength, 0));
        }

        public unsafe void InterimHash(byte* hash, int hashSize)
        {
            SafeBCryptHashHandle returnPtr;
            ExceptionHelper.CheckReturnCode(BCryptDuplicateHash(_hash, out returnPtr, IntPtr.Zero, 0, 0));
            ExceptionHelper.CheckReturnCode(BCryptFinishHash(returnPtr, (IntPtr)hash, hashSize, 0));
        }

        public void Dispose()
        {
            _hash.Dispose();
            GC.SuppressFinalize(this);
        }

        ~HashInstance()
        {
            Dispose();
        }
    }
}
