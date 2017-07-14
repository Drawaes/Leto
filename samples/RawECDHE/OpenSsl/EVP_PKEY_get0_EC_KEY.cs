using System.Runtime.InteropServices;

namespace Leto.OpenSsl11.Interop
{
    internal static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal static extern EC_KEY EVP_PKEY_get0_EC_KEY(EVP_PKEY key);
    }
}
