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
        private TlsVersion _version;
        private ushort _length;

        public TlsVersion Version { get => Reverse(_version); set => _version = Reverse(value); }
        public ushort Length { get => Reverse(_length); set => _length = Reverse(value); }
    }
}
