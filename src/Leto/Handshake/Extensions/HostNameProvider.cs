using System;
using System.Collections.Generic;
using System.Text;
using Leto.Internal;

namespace Leto.Handshake.Extensions
{
    public class HostNameProvider
    {
        //This can be extended to check that we match a list of servernames
        //or any other logic that is required
        public string ProcessHostNameExtension(BigEndianAdvancingSpan buffer)
        {
            buffer = buffer.ReadVector<ushort>();
            var type = buffer.Read<byte>();
            if(type != 0)
            {
                Alerts.AlertException.ThrowDecode("Unknown host type");
            }
            buffer = buffer.ReadVector<ushort>();
            return buffer.ToSpan().DecodeAscii();
        }
    }
}
