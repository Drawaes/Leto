using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    internal static partial class Sys
    {
        [DllImport(Libraries.SystemNative, EntryPoint = "SystemNative_MUnmap", SetLastError = true)]
        internal static extern int MUnmap(IntPtr addr, ulong len);
    }
}
