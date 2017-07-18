using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    public static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe BIGNUM BN_bin2bn(void* s, int len, IntPtr ptr);

        public static unsafe BIGNUM BN_bin2bn(ReadOnlySpan<byte> data)
        {
            fixed(void* dataPtr = &data.DangerousGetPinnableReference())
            {
                var result  = BN_bin2bn(dataPtr, data.Length, IntPtr.Zero);
                if (!result.IsValid) throw new InvalidOperationException("Unable to create a big number");
                return result;
            }
        }
    }
}
