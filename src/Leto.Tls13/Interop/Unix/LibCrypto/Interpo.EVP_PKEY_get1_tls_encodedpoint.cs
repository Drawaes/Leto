using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal static extern unsafe IntPtr EVP_PKEY_get1_tls_encodedpoint(EVP_PKEY pkey,out IntPtr ptr);
    }
}
