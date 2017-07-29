using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;

namespace LegacyOpenSsl.Interop
{
    internal unsafe static class LockStore
    {
        private static SemaphoreSlim[] _locks;
        internal static readonly LibCrypto.locking_function Callback;

        static LockStore()
        {
            var numberOfLocks = LibCrypto.CRYPTO_num_locks();
            _locks = new SemaphoreSlim[numberOfLocks];
            for (var i = 0; i < _locks.Length; i++)
            {
                _locks[i] = new SemaphoreSlim(1);
            }
            Callback = HandleLock;
        }

        private static unsafe void HandleLock(LibCrypto.LockState lockState, int lockId, byte* file, int lineNumber)
        {
            if ((lockState & LibCrypto.LockState.CRYPTO_UNLOCK) > 0)
            {
                _locks[lockId].Release();
            }
            else if ((lockState & LibCrypto.LockState.CRYPTO_LOCK) > 0)
            {
                _locks[lockId].Wait();
            }
        }
    }
}
