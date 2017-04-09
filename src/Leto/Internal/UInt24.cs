using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Internal
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct UInt24
    {
        private byte _b0;
        private byte _b1;
        private byte _b2;

        public static implicit operator UInt24(ushort val)
        {
            var returnVal = new UInt24()
            {
                _b0 = (byte)val,
                _b1 = (byte)(val >> 8)
            };
            return returnVal;
        }
        
        public static implicit operator int(UInt24 val)
        {
            var returnInt = new int();
            returnInt = val._b0;
            returnInt |= val._b1 << 8;
            returnInt |= val._b2 << 16;
            return returnInt;
        }
        
        public static explicit operator UInt24(int val)
        {
            var returnVal = new UInt24()
            {
                _b0 = (byte)val,
                _b1 = (byte)(val >> 8),
                _b2 = (byte)(val >> 16)
            };
            return returnVal;
        }
    }
}
