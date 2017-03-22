using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.OpenSsl11.Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern int EVP_PKEY_keygen(EVP_PKEY_CTX ctx, out EVP_PKEY ppkey);

        internal static void EVP_PKEY_keygen_function(int functionNid, out EVP_PKEY generatedKey)
        {
            var keyGenCtx = EVP_PKEY_CTX_new_id((EVP_PKEY_type)functionNid, IntPtr.Zero);
            try
            {
                var result = EVP_PKEY_keygen_init(keyGenCtx);
                ThrowOnErrorReturnCode(result);
                
                result = EVP_PKEY_keygen(keyGenCtx, out generatedKey);
                ThrowOnErrorReturnCode(result);
            }
            finally
            {
                keyGenCtx.Free();
            }
        }

        internal static void EVP_PKEY_keygen(EVP_PKEY keyParameters, out EVP_PKEY generatedKey)
        {
            var keyGenCtx = EVP_PKEY_CTX_new(keyParameters, IntPtr.Zero);
            try
            {
                var result = EVP_PKEY_keygen_init(keyGenCtx);
                ThrowOnErrorReturnCode(result);
                result = EVP_PKEY_keygen(keyGenCtx, out generatedKey);
                ThrowOnErrorReturnCode(result);
            }
            finally
            {
                keyGenCtx.Free();
            }
        }
    }
}
