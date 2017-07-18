using System.Runtime.InteropServices;

namespace Leto.Interop
{
    public static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        public static extern EC_KEY EVP_PKEY_get0_EC_KEY(EVP_PKEY key);
    }
}
