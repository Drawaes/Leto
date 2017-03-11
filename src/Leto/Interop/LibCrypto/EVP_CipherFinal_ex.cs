using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe int EVP_CipherFinal_ex(EVP_CIPHER_CTX ctx, void* outm, out int outl);

        internal unsafe static int EVP_CipherFinal_ex(EVP_CIPHER_CTX ctx)
        {
            var result = EVP_CipherFinal_ex(ctx, null, out int size);
            return ThrowOnErrorReturnCode(result);
        }
    }
}
