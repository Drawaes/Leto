using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, CharSet =CharSet.Ansi)]
        internal static extern unsafe int OBJ_txt2nid(string s);
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern unsafe int OBJ_ln2nid(string ln);
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern unsafe int OBJ_sn2nid(string sn);
    }
}
