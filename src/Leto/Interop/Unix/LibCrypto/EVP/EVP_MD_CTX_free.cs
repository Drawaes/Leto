using System;
using System.Runtime.InteropServices;

namespace Leto.Interop
{
    internal static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern void EVP_MD_CTX_free(IntPtr ctx);
    }
}
