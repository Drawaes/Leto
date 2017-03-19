using Leto.Certificates;
using Leto.Keyshares;
using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;

namespace Leto.Handshake
{
    public static class KeyExchangeWriter
    {
        public static WritableBuffer SendKeyExchange(WritableBuffer buffer, IKeyshare keyshare, SignatureScheme signatureScheme)
        {
            var messageLength = 4 + keyshare.KeyExchangeSize;
            buffer.Ensure(messageLength);
            var bookMark = buffer.Memory;
            buffer.WriteBigEndian(ECCurveType.named_curve);
            buffer.WriteBigEndian(keyshare.NamedGroup);
            buffer.WriteBigEndian((byte)keyshare.KeyExchangeSize);
            var keysWritten = keyshare.WritePublicKey(buffer.Memory.Span);
            buffer.Advance(keysWritten);

            buffer.WriteBigEndian(signatureScheme);

            BufferExtensions.WriteVector<ushort>(ref buffer, (writer) =>
            {
                var tempBuffer = new byte[TlsConstants.RandomLength * 2 + messageLength];
                var tmpSpan = new Span<byte>(tempBuffer);
            //    connectionState.ClientRandom.CopyTo(tmpSpan);
                tmpSpan = tmpSpan.Slice(TlsConstants.RandomLength);
            //    connectionState.ServerRandom.CopyTo(tmpSpan);
                tmpSpan = tmpSpan.Slice(TlsConstants.RandomLength);
                bookMark.Span.Slice(0, messageLength).CopyTo(tmpSpan);
            //    connectionState.Certificate.SignHash(connectionState.CryptoProvider.HashProvider,
            //        connectionState.SignatureScheme, ref writer, tempBuffer, connectionState.ClientRandom.Length * 2 + messageLength);
                return writer;
            });
            throw new NotImplementedException();
        }
    }
}
