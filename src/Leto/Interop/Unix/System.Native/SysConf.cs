using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.Interop
{
    internal static partial class Sys
    {
        internal enum SysConfName
        {
            _SC_CLK_TCK = 1,
            _SC_PAGESIZE = 2,
            _SC_NPROCESSORS_ONLN = 3,
        }

        [DllImport(Libraries.SystemNative, EntryPoint = "SystemNative_SysConf", SetLastError = true)]
        internal static extern long SysConf(SysConfName name);
    }
}
