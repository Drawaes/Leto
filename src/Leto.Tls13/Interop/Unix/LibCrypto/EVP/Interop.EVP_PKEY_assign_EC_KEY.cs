using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int EVP_PKEY_assign(EVP_PKEY pkey,EVP_PKEY_type keyType, IntPtr key);

        internal static int EVP_PKEY_assign_EC_KEY(EVP_PKEY pkey, EC_KEY key) => EVP_PKEY_assign(pkey, EVP_PKEY_type.EVP_PKEY_EC, key.Ptr);
    }
}
