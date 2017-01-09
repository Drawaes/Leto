using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal static extern unsafe int EVP_PKEY_encrypt(EVP_PKEY_CTX ctx, byte* outBuffer, IntPtr outlen, byte* inBuffer, IntPtr inlen);
    }
}
