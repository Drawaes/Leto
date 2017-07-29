using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace LegacyOpenSsl.Interop
{
    public static partial class OpenSsl
    {
        public enum TLS_VERSION
        {
            TLS1_1_VERSION = 0x0302,
            TLS1_2_VERSION = 0x0303,
            TLS1_3_VERSION = 0x0304
        }
    }
}
