using System.Runtime.InteropServices;

namespace Leto.OpenSsl11.Interop
{
    internal static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, EntryPoint =nameof(EC_KEY_set_public_key))]
        private static extern int Internal_EC_KEY_set_public_key(EC_KEY key, EC_POINT point);

        internal static void EC_KEY_set_public_key(EC_KEY key, EC_POINT point)
        {
            var result = Internal_EC_KEY_set_public_key(key, point);
            ThrowOnErrorReturnCode(result);
        }
    }
}
