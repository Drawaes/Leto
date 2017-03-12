using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe int EVP_DigestFinal_ex(EVP_MD_CTX ctx, void* md, ref int s);

        internal unsafe static int EVP_DigestFinal_ex(EVP_MD_CTX ctx, Span<byte> output)
        {
            fixed(void* ptr = &output.DangerousGetPinnableReference())
            {
                int size = output.Length;
                var result = EVP_DigestFinal_ex(ctx, ptr, ref size);
                ThrowOnErrorReturnCode(result);
                return size;
            }
        }
    }
}
