using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    public static partial class OpenSsl
    {
        public class SSL :SafeHandle
        {
            private SSL() : base(IntPtr.Zero, true)
            {
            }

            public override bool IsInvalid => handle == IntPtr.Zero;

            protected override bool ReleaseHandle()
            {
                SSL_free(handle);
                return true;
            }
        }
    }
}
