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
    public class Server13ConnectionState : IConnectionState
    {
        public CipherSuite CipherSuite => throw new NotImplementedException();

        public IHash HandshakeHash => throw new NotImplementedException();

        public TlsVersion RecordVersion => throw new NotImplementedException();

        public AeadBulkCipher ReadKey => throw new NotImplementedException();

        public AeadBulkCipher WriteKey => throw new NotImplementedException();

        public bool HandshakeComplete => throw new NotImplementedException();

        public void ChangeCipherSpec()
        {
            throw new NotImplementedException();
        }

        public WritableBufferAwaitable HandleClientHello(ClientHelloParser clientHelloParser)
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }
    }
}
