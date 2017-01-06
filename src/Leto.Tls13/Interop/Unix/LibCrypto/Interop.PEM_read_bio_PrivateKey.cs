using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal static extern unsafe EVP_PKEY PEM_read_bio_PrivateKey(BIO bp, EVP_PKEY* x, void* cb, void* u);
    }
}
