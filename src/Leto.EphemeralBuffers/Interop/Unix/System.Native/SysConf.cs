using System;
using System.Runtime.InteropServices;

namespace Leto.EphemeralBuffers.Interop
{
    internal static partial class Sys
    {
        internal enum SysConfName
        {
            _SC_CLK_TCK = 1,
            _SC_PAGESIZE = 2,
            _SC_NPROCESSORS_ONLN = 3,
        }

        [DllImport("libc.so.6", EntryPoint = "sysconf")]
        internal static extern IntPtr SysConf(SysConfName name);
    }
}
