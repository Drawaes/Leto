using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    public partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        public static extern void BIO_set_retry_reason(BIO a, RetryReason ptr);

        [Flags]
        public enum RetryReason
        {
            BIO_FLAGS_READ = 0x01,
            BIO_FLAGS_WRITE = 0x02,
            BIO_FLAGS_IO_SPECIAL = 0x04,
            BIO_FLAGS_RWS = (BIO_FLAGS_READ | BIO_FLAGS_WRITE | BIO_FLAGS_IO_SPECIAL),
            BIO_FLAGS_SHOULD_RETRY = 0x08,
        }
    }
}
