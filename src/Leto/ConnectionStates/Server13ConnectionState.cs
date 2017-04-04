using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Leto.BulkCiphers;
using Leto.CipherSuites;
using Leto.Handshake;
using Leto.Hashes;
using System.IO.Pipelines;
using System.Net.Http;

namespace Leto.ConnectionStates
{
    public sealed class Server13ConnectionState : ConnectionState, IConnectionState
    {
        public Server13ConnectionState(SecurePipeConnection secureConnection)
            : base(secureConnection)
        {
        }

        public TlsVersion RecordVersion => TlsVersion.Tls12;

        public void ChangeCipherSpec()
        {
            Alerts.AlertException.ThrowUnexpectedMessage(RecordLayer.RecordType.ChangeCipherSpec);
        }

        public WritableBufferAwaitable HandleClientHello(ref ClientHelloParser clientHello)
        {
            CipherSuite = _cryptoProvider.CipherSuites.GetCipherSuite(TlsVersion.Tls13Draft18, clientHello.CipherSuites);
            HandshakeHash = _cryptoProvider.HashProvider.GetHash(CipherSuite.HashType);
            HandshakeHash.HashData(clientHello.OriginalMessage);
            ParseExtensions(ref clientHello);

            throw new NotImplementedException();
        }

        protected override void HandleExtension(ExtensionType extensionType, Span<byte> buffer)
        {
            switch (extensionType)
            {
                case ExtensionType.supported_groups:
                    if (KeyExchange == null)
                    {
                        KeyExchange = _cryptoProvider.KeyExchangeProvider.GetKeyExchangeFromSupportedGroups(buffer);
                    }
                    break;
                case ExtensionType.key_share:
                    if (KeyExchange?.HasPeerKey == true)
                    {
                        return;
                    }
                    KeyExchange = _cryptoProvider.KeyExchangeProvider.GetKeyExchange(buffer);
                    break;
                case ExtensionType.SessionTicket:
                    break;
                default:
                    throw new NotImplementedException();
            }
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
        }
    }
}
