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
using System.Threading.Tasks;
using Leto.Certificates;

namespace Leto.ConnectionStates
{
    public sealed class Server12ConnectionState : IConnectionState
    {
        private byte[] _clientRandom;
        private CipherSuite _cipherSuite;
        private SecurePipeConnection _secureConnection;
        private ApplicationLayerProtocolType _negotiatedAlpn;
        private IKeyshare _keyshare;
        private bool _secureRenegotiation;
        private IHash _handshakeHash;
        private ICertificate _certificate;
        private SignatureScheme _signatureScheme;

        public Server12ConnectionState(SecurePipeConnection secureConnection)
        {
            _secureConnection = secureConnection;
        }

        public CipherSuite CipherSuite => _cipherSuite;
        public ApplicationLayerProtocolType NegotiatedAlpn => _negotiatedAlpn;
        internal bool SecureRenegotiationSupported => _secureRenegotiation;
        internal SecurePipeConnection SecureConnection => _secureConnection;
        public IHash HandshakeHash => _handshakeHash;
        public ushort RecordVersion => (ushort)TlsVersion.Tls12;

        private void ParseExtensions(ref ClientHelloParser clientHello)
        {
            foreach (var (extensionType, buffer) in clientHello.Extensions)
            {
                switch (extensionType)
                {
                    case ExtensionType.application_layer_protocol_negotiation:
                        _negotiatedAlpn = _secureConnection.Listener.AlpnProvider.ProcessExtension(buffer);
                        break;
                    case ExtensionType.supported_groups:
                        _keyshare = _secureConnection.Listener.CryptoProvider.KeyshareProvider.GetKeyshare(_cipherSuite.KeyExchange, buffer);
                        break;
                    case ExtensionType.signature_algorithms:
                        break;
                    case ExtensionType.renegotiation_info:
                        _secureConnection.Listener.SecureRenegotiationProvider.ProcessExtension(buffer);
                        _secureRenegotiation = true;
                        break;
                    default:
                        throw new NotImplementedException();
                }
            }
        }

        public Task HandleHandshakeRecord(ReadableBuffer record)
        {
            throw new NotImplementedException();
        }

        public Task HandleChangeCipherSpecRecord(ReadableBuffer record)
        {
            throw new NotImplementedException();
        }

        public async Task HandleClientHello(ClientHelloParser clientHello)
        {
            _clientRandom = clientHello.ClientRandom.ToArray();
            _cipherSuite = _secureConnection.Listener.CryptoProvider.CipherSuites.GetCipherSuite(TlsVersion.Tls12, clientHello.CipherSuites);
            _handshakeHash = _secureConnection.Listener.CryptoProvider.HashProvider.GetHash(_cipherSuite.HashType);
            ParseExtensions(ref clientHello);
            if (_keyshare == null)
            {
                _keyshare = _secureConnection.Listener.CryptoProvider.KeyshareProvider.GetKeyshare(_cipherSuite.KeyExchange, default(Span<byte>));
            }
            var writer = _secureConnection.HandshakePipe.Writer.Alloc();
            WriteServerHello(ref writer);
            WriteCertificates(ref writer);
            if(_keyshare.RequiresServerKeyExchange)
            {

            }
            WriteServerHelloDone(ref writer);
            await writer.FlushAsync();
            await _secureConnection.RecordHandler.WriteRecords(_secureConnection.HandshakePipe.Reader, RecordType.Handshake);
        }

        private void WriteServerHelloDone(ref WritableBuffer writer)
        {
            WriteHandshake(ref writer, (buffer) =>
            {
                return buffer;
            }, HandshakeType.server_hello_done);
        }

        private void WriteCertificates(ref WritableBuffer writer)
        {
            WriteHandshake(ref writer, (buffer) =>
            {
                return CertificateWriter.WriteCertificates(buffer, _certificate);
            }, HandshakeType.certificate);
        }

        private void WriteServerHello(ref WritableBuffer writer)
        {
            WriteHandshake(ref writer, (buffer) =>
            {
                return ServerHelloWriter.Write(buffer, this);
            }, HandshakeType.server_hello);
        }

        private void WriteHandshake(ref WritableBuffer writer, Func<WritableBuffer, WritableBuffer> contentWriter, HandshakeType handshakeType)
        {
            var dataWritten = writer.BytesWritten;
            writer.WriteBigEndian(handshakeType);
            BufferExtensions.WriteVector24Bit(ref writer, contentWriter);
            if (HandshakeHash != null)
            {
                var hashBuffer = writer.AsReadableBuffer().Slice(dataWritten);
                HandshakeHash.HashData(hashBuffer);
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
