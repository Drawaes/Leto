using System.Runtime.InteropServices;

namespace Leto.Interop
{
    public static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        public static extern EC_POINT EC_KEY_get0_public_key(EC_KEY key);
    }
}
