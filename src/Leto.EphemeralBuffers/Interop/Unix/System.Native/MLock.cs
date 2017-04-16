using System;
using System.Runtime.InteropServices;

namespace Leto.EphemeralBuffers.Interop
{
    internal static partial class Sys
    {
        [DllImport("libc.so.6", EntryPoint ="mlock")]
        internal static extern int MLock(IntPtr addr, UIntPtr len);

        [DllImport("libc.so.6", EntryPoint ="munlock")]
        internal static extern int MUnlock(IntPtr addr, UIntPtr len);
    }

}
