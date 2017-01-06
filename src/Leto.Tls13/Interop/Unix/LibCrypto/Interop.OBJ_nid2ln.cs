using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "OBJ_nid2ln")]
        private static extern IntPtr Internal_OBJ_nid2ln(int nid);

        public static string OBJ_nid2ln(int nid)
        {
            var ptr = Internal_OBJ_nid2ln(nid);
            return Marshal.PtrToStringAnsi(ptr);
        }
    }
}