using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;

namespace Leto.OpenSslFacts
{
    public class TestingCryptoProvider:OpenSsl11.OpenSslCryptoProvider
    {
        public unsafe override void FillWithRandom(Span<byte> span)
        {
            fixed (void* ptr = &span.DangerousGetPinnableReference())
            {
                Unsafe.InitBlockUnaligned(ptr, 0, (uint)span.Length);
            }
        }
    }
}
