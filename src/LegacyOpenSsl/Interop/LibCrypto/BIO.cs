using System;
using System.Collections.Generic;
using System.Text;

namespace LegacyOpenSsl.Interop
{
    public static partial class LibCrypto
    {
        public struct BIO
        {
            private IntPtr _pointer;

            public void Free()
            {
                if (_pointer != IntPtr.Zero)
                {
                    BIO_free(this);
                    _pointer = IntPtr.Zero;
                }
            }
        }
    }
}
