using System;
using System.Runtime.InteropServices;

namespace Leto.OpenSsl11.Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern int EVP_PKEY_paramgen(EVP_PKEY_CTX ctx, out EVP_PKEY ppkey);

        internal static void EVP_PKEY_paramgen_ECCurve(int curveNid, out EVP_PKEY curveParameters)
        {
            const EVP_PKEY_Ctrl_OP op = EVP_PKEY_Ctrl_OP.EVP_PKEY_OP_PARAMGEN | EVP_PKEY_Ctrl_OP.EVP_PKEY_OP_KEYGEN;
            const EVP_PKEY_Ctrl_Command cmd = EVP_PKEY_Ctrl_Command.EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID;

            var ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_type.EVP_PKEY_EC, IntPtr.Zero);
            try
            {
                var result = EVP_PKEY_paramgen_init(ctx);
                ThrowOnErrorReturnCode(result);
                result = EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_type.EVP_PKEY_EC, op, cmd, curveNid, IntPtr.Zero);
                ThrowOnErrorReturnCode(result);
                result = EVP_PKEY_paramgen(ctx, out curveParameters);
            }
            finally
            {
                ctx.Free();
            }
        }
    }
}
