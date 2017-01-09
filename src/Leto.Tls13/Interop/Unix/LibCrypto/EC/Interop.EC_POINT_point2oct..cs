using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal static extern unsafe IntPtr EC_POINT_point2oct(EC_GROUP group, EC_POINT p, EC_POINT_CONVERSION form, void* buf, IntPtr len, IntPtr ctx);
    }
}
