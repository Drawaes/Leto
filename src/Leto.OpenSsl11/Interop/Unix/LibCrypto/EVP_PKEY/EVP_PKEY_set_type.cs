using System.Runtime.InteropServices;

namespace Leto.OpenSsl11.Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int EVP_PKEY_set_type(EVP_PKEY key, int nid);
    }
}
