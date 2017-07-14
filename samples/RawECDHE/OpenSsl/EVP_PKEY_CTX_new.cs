using System;
using System.Runtime.InteropServices;

namespace Leto.OpenSsl11.Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern EVP_PKEY_CTX EVP_PKEY_CTX_new(EVP_PKEY pkey, IntPtr e);
    }
}
