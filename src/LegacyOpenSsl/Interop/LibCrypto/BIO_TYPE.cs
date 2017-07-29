using System;
using System.Collections.Generic;
using System.Text;

namespace LegacyOpenSsl.Interop
{
    public static partial class LibCrypto
    {
        [Flags]
        public enum BIO_TYPE
        {
            BIO_TYPE_SOURCE_SINK = 0x0400,
            BIO_TYPE_MEM = 1 | BIO_TYPE_SOURCE_SINK | 2,
            BIO_TYPE_CUSTOM = 19 | BIO_TYPE_SOURCE_SINK,
        }
    }
}
