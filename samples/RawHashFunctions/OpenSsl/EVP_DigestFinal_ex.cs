using System;
using System.Runtime.InteropServices;

namespace Leto.OpenSsl11.Interop
{
    internal static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe int EVP_DigestFinal_ex(EVP_MD_CTX ctx, void* md, ref int s);

        internal unsafe static int EVP_DigestFinal_ex(EVP_MD_CTX ctx, Span<byte> output)
        {
            fixed(void* ptr = &output.DangerousGetPinnableReference())
            {
                var size = output.Length;
                var result = EVP_DigestFinal_ex(ctx, ptr, ref size);
                ThrowOnErrorReturnCode(result);
                return size;
            }
        }
    }
}
