using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal static extern EVP_PKEY_CTX EVP_PKEY_CTX_new_id(EVP_PKEY_type id, IntPtr e);
    }
}
