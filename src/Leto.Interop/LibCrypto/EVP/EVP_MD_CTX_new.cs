using System;
using System.Runtime.InteropServices;

namespace Leto.Interop
{
    public static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern EVP_MD_CTX EVP_MD_CTX_new();

        public static EVP_MD_CTX EVP_MD_CTX_new(EVP_HashType hashType)
        {
            var ctx = EVP_MD_CTX_new();
            var result = EVP_DigestInit_ex(ctx, hashType, IntPtr.Zero);
            ThrowOnErrorReturnCode(result);
            return ctx;
        }
    }
}
