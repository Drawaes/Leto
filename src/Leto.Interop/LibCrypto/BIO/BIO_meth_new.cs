using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    public static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern BIO_METHOD BIO_meth_new(int type, string name);
    }
}
