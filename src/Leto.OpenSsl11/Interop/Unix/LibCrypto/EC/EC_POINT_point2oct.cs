using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.OpenSsl11.Interop
{
    internal static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe IntPtr EC_POINT_point2oct(EC_GROUP group, EC_POINT p, EC_POINT_CONVERSION form, void* buf, IntPtr len, IntPtr ctx);

        internal unsafe static int EC_POINT_point2oct(EC_GROUP group, EC_POINT point, EC_POINT_CONVERSION form, Span<byte> output)
        {
            var size = EC_POINT_point2oct(group, point, form, null, IntPtr.Zero, IntPtr.Zero);
            if(size.ToInt32() > output.Length)
            {
                ExceptionHelper.ThrowException(new ArgumentOutOfRangeException(nameof(output)));
            }
            ThrowOnError(size);
            fixed(void* outputPtr = &output.DangerousGetPinnableReference())
            {
                size = EC_POINT_point2oct(group, point, form, outputPtr, (IntPtr)output.Length, IntPtr.Zero);
                ThrowOnError(size);
                return size.ToInt32();
            }
        }
    }
}
