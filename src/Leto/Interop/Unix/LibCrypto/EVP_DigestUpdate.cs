using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    internal partial class LibCrypto
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
