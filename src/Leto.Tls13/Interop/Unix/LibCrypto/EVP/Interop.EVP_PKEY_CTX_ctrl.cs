using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal static extern unsafe int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX ctx, EVP_PKEY_type keyType, EVP_PKEY_Ctrl_OP optype, EVP_PKEY_Ctrl_Command cmd, int p1, void* p2);
    }
}
