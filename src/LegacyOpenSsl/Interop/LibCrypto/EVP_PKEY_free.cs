using System;
using System.Runtime.InteropServices;

namespace LegacyOpenSsl.Interop
{
    public static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern void EVP_PKEY_free(IntPtr pKey);
    }
}
