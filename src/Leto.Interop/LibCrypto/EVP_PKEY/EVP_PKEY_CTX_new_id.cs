using System;
using System.Runtime.InteropServices;

namespace Leto.Interop
{
    public static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern EVP_PKEY_CTX EVP_PKEY_CTX_new_id(EVP_PKEY_type id, IntPtr e);
    }
}
