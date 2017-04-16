using System;
using System.Runtime.InteropServices;

namespace Leto.EphemeralBuffers.Interop
{
    internal static partial class Sys
    {
        [DllImport("libc.so.6")]
        internal static extern int munmap(IntPtr addr, UIntPtr len);
    }
}
