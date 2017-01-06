using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl,CharSet = CharSet.Ansi)]
        internal static extern void CRYPTO_clear_free(IntPtr ptr, UIntPtr num, string file, int line);
    }
}
