using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.State;

namespace Leto.Tls13.Handshake
{
    public class SessionKeys
    {
        const int TicketLifeTimeInHours = 24;

        public static WritableBuffer CreateNewSessionKey(WritableBuffer buffer, IConnectionState state)
        {
            var lifetime = TicketLifeTimeInHours * 60 * 60;
            buffer.WriteBigEndian((uint)lifetime);
            buffer.Ensure(4);
            state.CryptoProvider.FillWithRandom(buffer.Memory.Slice(0, 4));
            buffer.Advance(4);

            BufferExtensions.WriteVector<ushort>(ref buffer, (writer, conn) =>
            {
                state.ResumptionProvider.GenerateSessionTicket(ref writer, conn);
                return writer;
            }, state);

            BufferExtensions.WriteVector<ushort>(ref buffer, (writer, conn) =>
            {
                writer.WriteBigEndian(ExtensionType.ticket_early_data_info);
                writer.WriteBigEndian<ushort>(sizeof(uint));
                uint maxData = 1024*2;
                writer.WriteBigEndian(maxData);
                return writer;

            }, state);
            return buffer;
        }
    }
}
