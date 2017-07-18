using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    public static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, EntryPoint = nameof(DH_generate_key))]
        private static extern int Internal_DH_generate_key(DH dh);

        public static void DH_generate_key(DH dh)
        {
            var result = Internal_DH_generate_key(dh);
            ThrowOnErrorReturnCode(result);
        }
    }
}
