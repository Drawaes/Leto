using System;
using System.Collections.Generic;
using System.Runtime;
using System.Runtime.InteropServices;
using static Leto.BufferExtensions;

namespace Leto.RecordLayer
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct RecordHeader
    {
        public RecordType RecordType;
        public ushort RecordVersion;
        private ushort _recordLength;

        public ushort RecordLength { get => Reverse(_recordLength); set => _recordLength = Reverse(value); }
    }
}
