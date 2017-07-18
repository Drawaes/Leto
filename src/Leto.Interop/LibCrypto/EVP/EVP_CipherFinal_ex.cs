using System;
using System.Runtime.InteropServices;

namespace Leto.Interop
{
    public static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern int EVP_CipherFinal_ex(EVP_CIPHER_CTX ctx, IntPtr outm, out int outl);

        public static int EVP_CipherFinal_ex(EVP_CIPHER_CTX ctx)
        {
            var result = EVP_CipherFinal_ex(ctx, IntPtr.Zero, out int size);
            return ThrowOnErrorReturnCode(result);
        }
    }
}
