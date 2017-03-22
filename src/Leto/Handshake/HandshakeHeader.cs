using System.Runtime.InteropServices;

namespace Leto.Handshake
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct HandshakeHeader
    {
        public HandshakeType MessageType;
        private byte _firstByte;
        private ushort _secondBytes;

        public uint Length
        {
            get =>
                (uint)(((_secondBytes & 0xFF00) >> 8)
                | ((_secondBytes & 0x00FF) << 8)
                | (_firstByte << 16));
            set
            {
                _firstByte = (byte)(value >> 16);
                _secondBytes = (ushort)(((value & 0x0000FF00) >> 8) | ((value & 0x000000FF) << 8));
            }
        }
    }
}
