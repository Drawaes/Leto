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

namespace Leto.ConnectionStates
{
    public class ServerUnknownVersionState : IConnectionState
    {
        private Action<IConnectionState> _replaceConnectionState;
        private ISecurePipeListener _listener;

        private static TlsVersion[] s_supportedVersions =
        {
            TlsVersion.Tls13Draft18,
            TlsVersion.Tls12,
        };

        public CipherSuite CipherSuite => throw new InvalidOperationException("Version selecting state does not have a cipher suite");
        public ApplicationLayerProtocolType Alpn { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public IHash HandshakeHash => throw new NotImplementedException();

        public ServerUnknownVersionState(Action<IConnectionState> replaceConnectionState, ISecurePipeListener listener)
        {
            _replaceConnectionState = replaceConnectionState;
            _listener = listener;
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

        public void HandleHandshakeRecord(ref ReadableBuffer record, ref WritableBuffer writer)
        {
            var header = record.ReadLittleEndian<HandshakePrefix>();
            if (header.MessageType != HandshakeType.client_hello)
            {
                Alerts.AlertException.ThrowUnexpectedMessage(header.MessageType);
            }
            var helloParser = new ClientHelloParser(ref record);
            var version = GetVersion(ref helloParser);
            IConnectionState connectionState;
            switch (version)
            {
                case TlsVersion.Tls12:
                    connectionState = new Server12ConnectionState(_listener);
                    break;
                case TlsVersion.Tls13Draft18:
                    throw new NotImplementedException();
                default:
                    throw new NotImplementedException();
            }
            connectionState.HandleClientHello(ref helloParser, ref writer);
            _replaceConnectionState(connectionState);
        }

        public void HandleChangeCipherSpecRecord(ref ReadableBuffer record, ref WritableBuffer writer)
        {
            Alerts.AlertException.ThrowUnexpectedMessage(RecordType.ChangeCipherSpec);
        }

        public void HandleApplicationRecord(ref ReadableBuffer record, ref WritableBuffer writer)
        {
            Alerts.AlertException.ThrowUnexpectedMessage(RecordLayer.RecordType.Application);
        }

        public void HandAlertRecord(ref ReadableBuffer record, ref WritableBuffer writer)
        {
            Alerts.AlertException.ThrowUnexpectedMessage(RecordLayer.RecordType.Alert);
        }

        public void HandleClientHello(ref ClientHelloParser clientHelloParser, ref WritableBuffer writer)
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            //The version selector has no resources to cleanup
        }
    }
}
