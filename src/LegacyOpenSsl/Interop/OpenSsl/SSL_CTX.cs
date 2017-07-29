using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace LegacyOpenSsl.Interop
{
    public static partial class OpenSsl
    {
        public class SSL_CTX:SafeHandle
        {
            private SSL_CTX() : base(IntPtr.Zero, true)
            {
            }

            public override bool IsInvalid => handle == IntPtr.Zero;

            protected override bool ReleaseHandle()
            {
                if (IsInvalid) return false;

                SSL_CTX_free(handle);

                return true;
            }
        }
    }
}
