using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using Leto.Handshake;
using Leto.RecordLayer;
using Leto.CipherSuites;

namespace Leto.ConnectionStates
{
    public class Server12ConnectionState : IConnectionState
    {
        private byte[] _clientRandom;
        private CipherSuite _cipherSuite;
        private ICryptoProvider _cryptoProvider;

        public Server12ConnectionState(ref ClientHelloParser clientHello, ICryptoProvider cryptoProvider)
        {
            _cryptoProvider = cryptoProvider;
            _clientRandom = clientHello.ClientRandom.ToArray();
            _cipherSuite = cryptoProvider.CipherSuites.GetCipherSuite(TlsVersion.Tls12, clientHello.CipherSuites);
        }

        public CipherSuite CipherSuite => _cipherSuite;
        
        public void HandleHandshakeRecord(ref ReadableBuffer record, ref WritableBuffer writer)
        {
            throw new NotImplementedException();
        }

        public void HandleChangeCipherSpecRecord(ref ReadableBuffer record, ref WritableBuffer writer)
        {
            throw new NotImplementedException();
        }

        public void HandleApplicationRecord(ref ReadableBuffer record, ref WritableBuffer writer)
        {
            throw new NotImplementedException();
        }

        public void HandAlertRecord(ref ReadableBuffer record, ref WritableBuffer writer)
        {
            throw new NotImplementedException();
        }
    }
}
