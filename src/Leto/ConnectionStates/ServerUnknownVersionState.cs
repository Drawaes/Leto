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
using Leto.Keyshares;

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
        public ushort RecordVersion => (ushort)TlsVersion.Tls1;
        public AeadBulkCipher ReadKey => null;
        public AeadBulkCipher WriteKey => null;
        public bool HandshakeComplete => throw new NotImplementedException();
        public ICertificate Certificate => throw new NotImplementedException();
        public IKeyshare Keyshare => throw new NotImplementedException();
        public SignatureScheme SignatureScheme => throw new NotImplementedException();

        public ServerUnknownVersionState(Action<IConnectionState> replaceConnectionState, SecurePipeConnection securePipe)
        {
            _replaceConnectionState = replaceConnectionState;
            _securePipe = securePipe;
            var ignore = ReadLoop();
        }

        private async Task ReadLoop()
        {
            while (true)
            {
                var reader = await _securePipe.HandshakeInput.Reader.ReadAsync();
                var buffer = reader.Buffer;
                HandshakeFraming.ReadHandshakeFrame(ref buffer, out ReadableBuffer handshake, out HandshakeType recordType);
                if (recordType != HandshakeType.client_hello)
                {
                    _securePipe.HandshakeInput.Reader.Advance(buffer.Start, buffer.End);
                    if (recordType == HandshakeType.none)
                    {
                        continue;
                    }
                    Alerts.AlertException.ThrowUnexpectedMessage(recordType);
                }
                IConnectionState connectionState;
                ClientHelloParser helloParser;
                try
                {
                    helloParser = new ClientHelloParser(handshake);
                    var version = GetVersion(ref helloParser);
                    switch (version)
                    {
                        case TlsVersion.Tls12:
                            connectionState = new Server12ConnectionState(_securePipe);
                            break;
                        case TlsVersion.Tls13Draft18:
                            throw new NotImplementedException();
                        default:
                            throw new NotImplementedException();
                    }
                    _replaceConnectionState(connectionState);
                }
                finally
                {
                    _securePipe.HandshakeInput.Reader.Advance(buffer.Start, buffer.Start);
                }
                await connectionState.HandleClientHello(helloParser);
                return;
            }
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

        public void ChangeCipherSpec()
        {
            Alerts.AlertException.ThrowUnexpectedMessage(RecordType.ChangeCipherSpec);
        }

        public Task HandleClientHello(ClientHelloParser clientHelloParser)
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            //The version selector has no resources to cleanup
        }
    }
}
