using System.Runtime.InteropServices;

namespace Leto.OpenSsl11.Interop
{
    internal static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern int EVP_PKEY_assign(EVP_PKEY pkey, EVP_PKEY_type keyType, EC_KEY key);

        internal static void EVP_PKEY_assign_EC_KEY(EVP_PKEY pkey, EC_KEY key)
        {
            var result = EVP_PKEY_assign(pkey, EVP_PKEY_type.EVP_PKEY_EC, key);
            ThrowOnErrorReturnCode(result);
        }
    }
}
