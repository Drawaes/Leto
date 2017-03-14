using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Handshake
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct HandshakePrefix
    {
        public HandshakeType MessageType;
        private byte _firstByte;
        private ushort _secondBytes;

        public uint Length
        {
            get => (uint)((_secondBytes << 8 & 0x00FF) + (_secondBytes >> 8) + _firstByte);
            set
            {
                _firstByte = (byte)(value << 16);
                _secondBytes = (ushort)((value & 0x00FFFF00) >> 8);
            }
        }
    }
}
