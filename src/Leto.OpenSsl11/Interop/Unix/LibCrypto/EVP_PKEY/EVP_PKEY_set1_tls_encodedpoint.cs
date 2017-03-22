using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.OpenSsl11.Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe int EVP_PKEY_set1_tls_encodedpoint(EVP_PKEY pkey, void* pt, UIntPtr ptlen);

        internal static unsafe void EVP_PKEY_set1_tls_encodedpoint(EVP_PKEY pkey, Span<byte> point)
        {
            fixed(void* ptr = &point.DangerousGetPinnableReference())
            {
                var result = EVP_PKEY_set1_tls_encodedpoint(pkey, ptr, (UIntPtr)point.Length);
                ThrowOnErrorReturnCode(result);
            }
        }
    }
}
