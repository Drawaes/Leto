using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace Leto.Tls13.Internal
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct UInt24
    {
        private ushort _lowerBytes;
        private byte _upperByte;

        public unsafe static implicit operator int(UInt24 d)
        {
            return Unsafe.Read<int>(&d);
        }

        public unsafe static explicit operator UInt24(int d)
        {
            return Unsafe.Read<UInt24>(&d);
        }
    }
}
