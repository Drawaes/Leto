using System;
using System.Runtime.InteropServices;

namespace Leto.Interop
{
    public static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX ctx, EVP_PKEY_type keyType, EVP_PKEY_Ctrl_OP optype, EVP_PKEY_Ctrl_Command cmd, int p1, IntPtr p2);
    }
}
