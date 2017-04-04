using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.Handshake.Extensions
{
    public class HostNameProvider
    {
        //This can be extended to check that we match a list of servernames
        //or any other logic that is required
        public string ProcessHostNameExtension(Span<byte> buffer)
        {
            buffer = BufferExtensions.ReadVector16(ref buffer);
            byte type;
            (type, buffer) = BufferExtensions.Consume<byte>(buffer);
            if(type != 0)
            {
                Alerts.AlertException.ThrowDecode("Unknown host type");
            }
            buffer = BufferExtensions.ReadVector16(ref buffer);
            return buffer.DecodeAscii();
        }
    }
}
