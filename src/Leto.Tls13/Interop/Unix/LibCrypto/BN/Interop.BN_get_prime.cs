using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal static extern BIGNUM BN_get_rfc3526_prime_2048(IntPtr bn);
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal static extern BIGNUM BN_get_rfc3526_prime_3072(IntPtr bn);
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal static extern BIGNUM BN_get_rfc3526_prime_4096(IntPtr bn);
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal static extern BIGNUM BN_get_rfc3526_prime_6144(IntPtr bn);
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal static extern BIGNUM BN_get_rfc3526_prime_8192(IntPtr bn);
    }
}
