using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal static extern unsafe int EC_POINT_oct2point(EC_GROUP group, EC_POINT p, void* buf, IntPtr len, void* ctx);
    }
}
