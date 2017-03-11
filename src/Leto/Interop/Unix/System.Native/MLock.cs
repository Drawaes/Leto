using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    internal static partial class Sys
    {
        [DllImport(Libraries.SystemNative, EntryPoint = "SystemNative_MLock", SetLastError = true)]
        internal static extern int MLock(IntPtr addr, ulong len);

        [DllImport(Libraries.SystemNative, EntryPoint = "SystemNative_MUnlock", SetLastError = true)]
        internal static extern int MUnlock(IntPtr addr, ulong len);
    }

}
