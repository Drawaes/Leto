using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        [StructLayout(LayoutKind.Sequential)]
        internal unsafe struct EC_builtin_curve
        {
            internal int nid;
            internal void* comment;
        }
    }
}
