using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int OPENSSL_init_crypto(OPENSSL_INIT_Options opts, IntPtr settings);

        [Flags]
        internal enum OPENSSL_INIT_Options : ulong
        {
            OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS = 0x00000001L,
            OPENSSL_INIT_LOAD_CRYPTO_STRINGS = 0x00000002L,
            OPENSSL_INIT_ADD_ALL_CIPHERS = 0x00000004L,
            OPENSSL_INIT_ADD_ALL_DIGESTS = 0x00000008L,
            OPENSSL_INIT_NO_ADD_ALL_CIPHERS = 0x00000010L,
            OPENSSL_INIT_NO_ADD_ALL_DIGESTS = 0x00000020L,
            OPENSSL_INIT_LOAD_CONFIG = 0x00000040L,
            OPENSSL_INIT_NO_LOAD_CONFIG = 0x00000080L,
            OPENSSL_INIT_ASYNC = 0x00000100L,
            OPENSSL_INIT_ENGINE_RDRAND = 0x00000200L,
            OPENSSL_INIT_ENGINE_DYNAMIC = 0x00000400L,
            OPENSSL_INIT_ENGINE_OPENSSL = 0x00000800L,
            OPENSSL_INIT_ENGINE_CRYPTODEV = 0x00001000L,
            OPENSSL_INIT_ENGINE_CAPI = 0x00002000L,
            OPENSSL_INIT_ENGINE_PADLOCK = 0x00004000L,
            OPENSSL_INIT_ENGINE_AFALG = 0x00008000L,
        }
    }
}
