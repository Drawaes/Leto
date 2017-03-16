using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using Leto.Handshake;
using Leto.RecordLayer;
using Leto.CipherSuites;
using Leto.Handshake.Extensions;
using Leto.Keyshares;

namespace Leto.ConnectionStates
{
    public class Server12ConnectionState : IConnectionState
    {
        private byte[] _clientRandom;
        private CipherSuite _cipherSuite;
        private ISecurePipeListener _listener;
        private ApplicationLayerProtocolType _negotiatedAlpn;
        private IKeyshare _keyshare;
        private bool _secureRenegotiation;
        
        public Server12ConnectionState(ISecurePipeListener listener)
        {
            _listener = listener;
        }

        public CipherSuite CipherSuite => _cipherSuite;
        public ApplicationLayerProtocolType NegotiatedAlpn => _negotiatedAlpn;
        public ISecurePipeListener Listener => _listener;

        private void ParseExtensions(ref ClientHelloParser clientHello)
        {
            foreach (var (extensionType, buffer) in clientHello.Extensions)
            {
                switch (extensionType)
                {
                    case ExtensionType.application_layer_protocol_negotiation:
                        _negotiatedAlpn = _listener.AlpnProvider.ProcessExtension(buffer);
                        break;
                    case ExtensionType.supported_groups:
                        _keyshare = _listener.CryptoProvider.KeyshareProvider.GetKeyshare(_cipherSuite.KeyExchange, buffer);
                        break;
                    case ExtensionType.signature_algorithms:
                        break;
                    case ExtensionType.renegotiation_info:
                        _listener.SecureRenegotiationProvider.ProcessExtension(buffer);
                        _secureRenegotiation = true;
                        break;
                    default:
                        throw new NotImplementedException();
                }
            }
        }

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

        public void HandleClientHello(ref ClientHelloParser clientHello, ref WritableBuffer writer)
        {
            _clientRandom = clientHello.ClientRandom.ToArray();
            _cipherSuite = _listener.CryptoProvider.CipherSuites.GetCipherSuite(TlsVersion.Tls12, clientHello.CipherSuites);
            ParseExtensions(ref clientHello);
            if(_keyshare == null)
            {
                _keyshare = _listener.CryptoProvider.KeyshareProvider.GetKeyshare(_cipherSuite.KeyExchange, default(Span<byte>));
            }
        }
    }
}
