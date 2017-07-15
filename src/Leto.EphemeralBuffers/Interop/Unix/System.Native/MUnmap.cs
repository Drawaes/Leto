using System;
using System.Runtime.InteropServices;

namespace Leto.EphemeralBuffers.Interop
{
    internal static partial class Sys
    {
        [DllImport("libc.so.6")]
#pragma warning disable IDE1006 // Naming Styles
        internal static extern int munmap(IntPtr addr, UIntPtr len);
#pragma warning restore IDE1006 // Naming Styles
    }
}
