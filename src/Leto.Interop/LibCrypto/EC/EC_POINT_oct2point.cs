using System;
using System.Runtime.InteropServices;

namespace Leto.Interop
{
    public static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe int EC_POINT_oct2point(EC_GROUP group, EC_POINT p, void* buf, IntPtr len, void* ctx);

        public unsafe static void EC_POINT_oct2point(EC_GROUP group, EC_POINT point, ReadOnlySpan<byte> buffer)
        {
            fixed (void* bufferPtr = &buffer.DangerousGetPinnableReference())
            {
                var result = EC_POINT_oct2point(group, point, bufferPtr, (IntPtr)buffer.Length, null);
                ThrowOnErrorReturnCode(result);
            }
        }
    }
}
