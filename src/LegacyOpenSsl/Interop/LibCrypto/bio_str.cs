using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace LegacyOpenSsl.Interop
{
    public static partial class LibCrypto
    {
        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct bio_st
        {
            public void* method;
            /* bio, mode, argp, argi, argl, ret */
            public void* callback;
            public void* cb_arg;               /* first argument for the callback */
            public int init;
            public int shutdown;
            public int flags;                  /* extra storage */
            public int retry_reason;
            public int num;
            public void* ptr;
        }
    }
}
