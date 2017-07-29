using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace LegacyOpenSsl.Interop
{
    public static partial class LibCrypto
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal unsafe delegate void locking_function(LockState mode, int threadNumber, byte* file, int line);

        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal extern static void CRYPTO_set_locking_callback(locking_function lockingFunction);

        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        public extern static void OPENSSL_add_all_algorithms_noconf();
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        public extern static void ERR_load_crypto_strings();

        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        public extern static int CRYPTO_num_locks();
        [DllImport(Libraries.LibSsl, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_load_error_strings();
        [DllImport(Libraries.LibSsl, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_library_init();
                
        [Flags]
        internal enum LockState
        {
            CRYPTO_UNLOCK = 0x02,
            CRYPTO_READ = 0x04,
            CRYPTO_LOCK = 0x01,
            CRYPTO_WRITE = 0x08,
        }
    }
}
