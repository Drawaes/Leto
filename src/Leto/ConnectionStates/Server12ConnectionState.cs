using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using Leto.Handshake;
using Leto.RecordLayer;
using Leto.CipherSuites;
using Leto.Handshake.Extensions;
using Leto.Keyshares;
using Leto.Hashes;

namespace Leto.ConnectionStates
{
    public sealed class Server12ConnectionState : IConnectionState
    {
        private byte[] _clientRandom;
        private CipherSuite _cipherSuite;
        private ISecurePipeListener _listener;
        private ApplicationLayerProtocolType _negotiatedAlpn;
        private IKeyshare _keyshare;
        private bool _secureRenegotiation;
        private IHash _handshakeHash;

        public Server12ConnectionState(ISecurePipeListener listener)
        {
            _listener = listener;
        }

        public CipherSuite CipherSuite => _cipherSuite;
        public ApplicationLayerProtocolType NegotiatedAlpn => _negotiatedAlpn;
        public ISecurePipeListener Listener => _listener;
        internal bool SecureRenegotiationSupported => _secureRenegotiation;
        public IHash HandshakeHash => _handshakeHash;

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

        public void HandleClientHello(ref ClientHelloParser clientHello, ref WritableBuffer writer)
        {
            _clientRandom = clientHello.ClientRandom.ToArray();
            _cipherSuite = _listener.CryptoProvider.CipherSuites.GetCipherSuite(TlsVersion.Tls12, clientHello.CipherSuites);
            _handshakeHash = _listener.CryptoProvider.HashProvider.GetHash(_cipherSuite.HashType);
            ParseExtensions(ref clientHello);
            if (_keyshare == null)
            {
                _keyshare = _listener.CryptoProvider.KeyshareProvider.GetKeyshare(_cipherSuite.KeyExchange, default(Span<byte>));
            }
            WriteHandshake(ref writer, (buffer) =>
            {
                return ServerHelloWriter12.Write(buffer, this);
            }, this, HandshakeType.server_hello);
        }

        private void WriteHandshake(ref WritableBuffer writer, Func<WritableBuffer, WritableBuffer> contentWriter, IConnectionState state, HandshakeType handshakeType)
        {
            var dataWritten = writer.BytesWritten;
            writer.WriteBigEndian(handshakeType);
            BufferExtensions.WriteVector24Bit(ref writer, contentWriter);
            if (state.HandshakeHash != null)
            {
                var hashBuffer = writer.AsReadableBuffer().Slice(dataWritten);
                state.HandshakeHash.HashData(hashBuffer);
            }
        }

        public void Dispose()
        {
            _handshakeHash?.Dispose();
            _handshakeHash = null;
            _keyshare?.Dispose();
            _keyshare = null;
        }

        ~Server12ConnectionState()
        {
            Dispose();
        }
    }
}
