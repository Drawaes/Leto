using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal static extern unsafe int PKCS12_parse(IntPtr p12, string pass, out EVP_PKEY pkey, out X509 cert, out IntPtr certStack);
    }
}
