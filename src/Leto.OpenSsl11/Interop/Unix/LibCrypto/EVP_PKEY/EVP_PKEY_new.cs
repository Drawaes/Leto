using System.Runtime.InteropServices;

namespace Leto.OpenSsl11.Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal static extern unsafe EVP_PKEY EVP_PKEY_new();
    }
}
