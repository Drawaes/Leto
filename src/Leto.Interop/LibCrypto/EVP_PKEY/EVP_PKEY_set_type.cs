using System.Runtime.InteropServices;

namespace Leto.Interop
{
    public static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        public static extern int EVP_PKEY_set_type(EVP_PKEY key, int nid);
    }
}
