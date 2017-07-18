using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    public static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, EntryPoint = nameof(BN_bn2binpad))]
        private static extern unsafe int BN_bn2binpad(BIGNUM a, void* to, int tolen);

        public static unsafe int BN_bn2binpad(BIGNUM a, Span<byte> buffer)
        {
            fixed(void* ptr = &buffer.DangerousGetPinnableReference())
            {
                return BN_bn2binpad(a, ptr, buffer.Length);
            }
        }
    }
}
