using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.OpenSsl11.Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe int RAND_bytes(void* buf, int num);

        internal static unsafe void RAND_bytes(Span<byte> span)
        {
            fixed(void* ptr = &span.DangerousGetPinnableReference())
            {
                var result = RAND_bytes(ptr, span.Length);
                ThrowOnErrorReturnCode(result);
            }
        }
    }
}
