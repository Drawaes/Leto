using System;
using System.Runtime.InteropServices;

namespace Leto.EphemeralBuffers.Interop
{
    internal static partial class Sys
    {
        [DllImport(Libraries.SystemNative, EntryPoint = "SystemNative_MUnmap", SetLastError = true)]
        internal static extern int MUnmap(IntPtr addr, ulong len);
    }
}
