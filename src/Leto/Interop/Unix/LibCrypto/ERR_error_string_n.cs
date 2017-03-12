using System;
using System.Runtime.InteropServices;

namespace Leto.Interop
{
    internal static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe void ERR_error_string_n(int e, byte* buf, UIntPtr len);
    }
}
