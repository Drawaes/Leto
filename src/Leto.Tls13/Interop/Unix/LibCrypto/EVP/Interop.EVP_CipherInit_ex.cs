using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal static extern unsafe int EVP_CipherInit_ex(EVP_CIPHER_CTX ctx, IntPtr type, IntPtr impl, void* key, void* iv, int enc);
    }
}
