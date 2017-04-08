using Leto.Handshake;
using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using static Leto.BufferExtensions;
using Leto.CipherSuites;
using Leto.RecordLayer;
using Leto.Handshake.Extensions;
using Leto.Hashes;
using System.Threading.Tasks;
using Leto.BulkCiphers;
using Leto.Certificates;
using Leto.KeyExchanges;

namespace Leto.ConnectionStates
{
    public class ServerUnknownVersionState : IConnectionState
    {
        private Action<IConnectionState> _replaceConnectionState;
        private SecurePipeConnection _securePipe;

        private static TlsVersion[] s_supportedVersions =
        {
            TlsVersion.Tls13Draft18,
            TlsVersion.Tls12,
        };

        public CipherSuite CipherSuite => throw new InvalidOperationException("Version selecting state does not have a cipher suite");
        public IHash HandshakeHash => throw new NotImplementedException();
        public TlsVersion RecordVersion => TlsVersion.Tls1;
        public AeadBulkCipher ReadKey => null;
        public AeadBulkCipher WriteKey => null;
        public bool HandshakeComplete => throw new NotImplementedException();

        public ServerUnknownVersionState(Action<IConnectionState> replaceConnectionState, SecurePipeConnection securePipe)
        {
            _replaceConnectionState = replaceConnectionState;
            _securePipe = securePipe;
        }

        public bool ProcessHandshake()
        {
            var hasReader = _securePipe.HandshakeInput.Reader.TryRead(out ReadResult reader);
            if (!hasReader) return false;
            var buffer = reader.Buffer;
            IConnectionState connectionState;
            ClientHelloParser helloParser;
            try
            {
                HandshakeFraming.ReadHandshakeFrame(ref buffer, out ReadableBuffer handshake, out HandshakeType recordType);
                if (recordType != HandshakeType.client_hello)
                {
                    _securePipe.HandshakeInput.Reader.Advance(buffer.Start, buffer.End);
                    if (recordType == HandshakeType.none)
                    {
                        return false;
                    }
                    Alerts.AlertException.ThrowUnexpectedMessage(recordType);
                }
                helloParser = new ClientHelloParser(handshake);
                var version = GetVersion(ref helloParser);
                switch (version)
                {
                    case TlsVersion.Tls12:
                        connectionState = new Server12ConnectionState(_securePipe);
                        break;
                    case TlsVersion.Tls13Draft18:
                        connectionState = new Server13ConnectionState(_securePipe);
                        break;
                    default:
                        throw new NotImplementedException();
                }
                _replaceConnectionState(connectionState);
            }
            finally
            {
                _securePipe.HandshakeInput.Reader.Advance(buffer.Start, buffer.Start);
            }
            return connectionState.HandleClientHello(ref helloParser);
        }

        private TlsVersion GetVersion(ref ClientHelloParser helloParser)
        {
            if (helloParser.Extensions == null)
            {
                return MatchVersionOrThrow(helloParser.TlsVersion);
            }
            var (ext, extBuffer) = helloParser.Extensions.SingleOrDefault((ex) => ex.Item1 == ExtensionType.supported_versions);
            if (extBuffer != default(Span<byte>))
            {
                var versionVector = ReadVector8(ref extBuffer);
                while (versionVector.Length > 0)
                {
                    var foundVersion = (TlsVersion)ReadBigEndian<ushort>(ref versionVector);
                    if (MatchVersion(foundVersion))
                    {
                        return foundVersion;
                    }
                }
            }
            return MatchVersionOrThrow(helloParser.TlsVersion);
        }

        private bool MatchVersion(TlsVersion tlsVersion)
        {
            foreach (var version in s_supportedVersions)
            {
                if (version == tlsVersion)
                {
                    return true;
                }
            }
            return false;
        }

        private TlsVersion MatchVersionOrThrow(TlsVersion tlsVersion)
        {
            if (!MatchVersion(tlsVersion))
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal,
                    Alerts.AlertDescription.protocol_version, $"Could not match {tlsVersion} to any supported version");
            }
            return tlsVersion;
        }

        public void ChangeCipherSpec() => Alerts.AlertException.ThrowUnexpectedMessage(RecordType.ChangeCipherSpec);

        public bool HandleClientHello(ref ClientHelloParser clientHelloParser) => throw new NotSupportedException();

        public void Dispose()
        {
            //The version selector has no resources to cleanup
        }
    }
}
