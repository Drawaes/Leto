using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Leto.BulkCiphers;
using Leto.CipherSuites;
using Leto.Handshake;
using Leto.Hashes;
using System.IO.Pipelines;

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

            throw new NotImplementedException();
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
        }
    }
}
