using System;
using System.Runtime.InteropServices;

namespace Leto.Interop
{
    internal static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe int EVP_DigestUpdate(EVP_MD_CTX ctx, void* d, int cnt);

        internal unsafe static int EVP_DigestUpdate(EVP_MD_CTX ctx, ReadOnlySpan<byte> span)
        {
            fixed(void* ptr = &span.DangerousGetPinnableReference())
            {
                var result = EVP_DigestUpdate(ctx, ptr, span.Length);
                ThrowOnErrorReturnCode(result);
                return result;
            }
        }
    }
}
