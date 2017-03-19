using Leto.Handshake;
using System;
using System.Collections.Generic;
using System.IO.Pipelines;

namespace Leto.ConnectionStates
{
    public sealed partial class Server12ConnectionState
    {
        private void SendFirstFlight(ref WritableBuffer writer)
        {
            WriteServerHelloTls12(ref writer);
            WriteCertificates(ref writer);
            WriteServerKeyExchange(ref writer);
            WriteServerHelloDone(ref writer);
        }

        private void WriteServerHelloDone(ref WritableBuffer writer)
        {
            HandshakeFraming.WriteHandshakeFrame(ref writer, _handshakeHash, (buffer) => buffer, HandshakeType.server_hello_done);
        }

        private void WriteCertificates(ref WritableBuffer writer)
        {
            HandshakeFraming.WriteHandshakeFrame(ref writer, _handshakeHash, (buffer) =>
            {
                return CertificateWriter.WriteCertificates(buffer, _certificate);
            }, HandshakeType.certificate);
        }

        private void WriteServerKeyExchange(ref WritableBuffer writer)
        {
            if (Keyshare.RequiresServerKeyExchange)
            {
                HandshakeFraming.WriteHandshakeFrame(ref writer, _handshakeHash,
                    (buffer) => KeyExchangeWriter.SendKeyExchange(buffer, Keyshare, _signatureScheme),
                    HandshakeType.server_key_exchange);
            }
        }

        private void WriteServerHelloTls12(ref WritableBuffer writer)
        {
            HandshakeFraming.WriteHandshakeFrame(ref writer, _handshakeHash, (buffer) =>
            {
                return ServerHelloWriter.Write(buffer, this);
            }, HandshakeType.server_hello);
        }
    }
}
