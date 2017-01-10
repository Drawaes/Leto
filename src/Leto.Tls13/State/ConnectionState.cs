using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Leto.Tls13.BulkCipher;
using Leto.Tls13.Certificates;
using Leto.Tls13.Handshake;
using Leto.Tls13.Hash;
using Leto.Tls13.Internal;
using Leto.Tls13.KeyExchange;
using Leto.Tls13.Sessions;

namespace Leto.Tls13.State
{
    public class ConnectionState : IDisposable
    {
        private StateType _state = StateType.None;
        private KeySchedule _keySchedule;
        private Signal _dataForCurrentScheduleSent = new Signal(Signal.ContinuationMode.Synchronous);
        private Signal _waitForHandshakeToChangeSchedule = new Signal(Signal.ContinuationMode.Synchronous);
        private SecurePipelineListener _listener;

        public ConnectionState(SecurePipelineListener listener)
        {
            _listener = listener;
            PskKeyExchangeMode = PskKeyExchangeMode.none;
        }

        public SecurePipelineListener Listener => _listener;
        public string ServerName { get; set; }
        public PskKeyExchangeMode PskKeyExchangeMode { get; set; }
        public IKeyshareInstance KeyShare { get; set; }
        public KeySchedule KeySchedule => _keySchedule;
        public ResumptionProvider ResumptionProvider => _listener.ResumptionProvider;
        public IHashInstance HandshakeHash { get; set; }
        public CryptoProvider CryptoProvider => _listener.CryptoProvider;
        public IBulkCipherInstance ReadKey { get; set; }
        public IBulkCipherInstance WriteKey { get; set; }
        public CertificateList CertificateList => _listener.CertificateList;
        public CipherSuite CipherSuite { get; internal set; }
        public StateType State => _state;
        public ushort Version { get; internal set; }
        public ICertificate Certificate { get; internal set; }
        internal Signal DataForCurrentScheduleSent => _dataForCurrentScheduleSent;
        internal Signal WaitForHandshakeToChangeSchedule => _waitForHandshakeToChangeSchedule;

        public SignatureScheme SignatureScheme { get; internal set; }

        internal void StartHandshakeHash(ReadableBuffer readable)
        {
            _dataForCurrentScheduleSent.Set();
            HandshakeHash = CryptoProvider.HashProvider.GetHashInstance(CipherSuite.HashType);
            HandshakeHash.HashData(readable);
        }

        internal void HandshakeContext(ReadableBuffer readable)
        {
            HandshakeHash.HashData(readable);
        }

        public async Task HandleMessage(HandshakeType handshakeMessageType, ReadableBuffer buffer, IPipelineWriter pipe)
        {
            WritableBuffer writer;
            switch (_state)
            {
                case StateType.None:
                case StateType.WaitHelloRetry:
                    if (handshakeMessageType != HandshakeType.client_hello)
                    {
                        Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.unexpected_message);
                    }
                    Hello.ReadClientHello(buffer, this);
                    if (!NegotiationComplete())
                    {
                        if (_state == StateType.WaitHelloRetry)
                        {
                            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure);
                        }
                        _state = StateType.WaitHelloRetry;
                        writer = pipe.Alloc();
                        WriteHandshake(ref writer, HandshakeType.hello_retry_request, Hello.SendHelloRetry);
                        await writer.FlushAsync();
                        return;
                    }
                    //Write the server hello, the last of the unencrypted messages
                    _state = StateType.SendServerHello;
                    writer = pipe.Alloc();
                    WriteHandshake(ref writer, HandshakeType.server_hello, Hello.SendServerHello);
                    //block our next actions because we need to have sent the message before changing keys
                    _dataForCurrentScheduleSent.Reset();
                    await writer.FlushAsync();
                    await _dataForCurrentScheduleSent;
                    _state = StateType.ServerAuthentication;
                    //Generate the encryption keys and send the next set of messages
                    GenerateHandshakeKeys();
                    writer = pipe.Alloc();
                    ServerHandshake.SendFlightOne(ref writer, this);
                    ServerHandshake.ServerFinished(ref writer, this, _keySchedule.GenerateServerFinishKey());
                    _dataForCurrentScheduleSent.Reset();
                    await writer.FlushAsync();
                    await _dataForCurrentScheduleSent;
                    _state = StateType.WaitClientFinished;
                    return;
                case StateType.WaitClientFinished:
                    if (handshakeMessageType != HandshakeType.finished)
                    {
                        Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.unexpected_message);
                    }
                    Finished.ReadClientFinished(buffer, this);
                    GenerateApplicationKeys();
                    //Hash the finish message now we have made the traffic keys
                    //Then we can make the resumption secret
                    HandshakeHash.HashData(buffer);
                    KeySchedule.GenerateResumptionSecret();
                    HandshakeHash.Dispose();
                    HandshakeHash = null;
                    //Send a new session ticket
                    writer = pipe.Alloc();
                    WriteHandshake(ref writer, HandshakeType.new_session_ticket, SessionKeys.CreateNewSessionKey);
                    await writer.FlushAsync();
                    _state = StateType.HandshakeComplete;
                    break;
                default:
                    Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.unexpected_message);
                    break;
            }
        }

        private bool NegotiationComplete()
        {
            if (KeyShare == null || Certificate == null)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.illegal_parameter);
            }
            if (!KeyShare.HasPeerKey)
            {
                return false;
            }
            return true;
        }

        private unsafe void GenerateApplicationKeys()
        {
            var hash = stackalloc byte[HandshakeHash.HashSize];
            var span = new Span<byte>(hash, HandshakeHash.HashSize);
            HandshakeHash.InterimHash(hash, HandshakeHash.HashSize);
            _keySchedule.GenerateMasterSecret(span);
        }

        private unsafe void GenerateHandshakeKeys()
        {
            _keySchedule = _listener.KeyScheduleProvider.GetKeySchedule(this);
            _keySchedule.SetDheDerivedValue(KeyShare);
            var hash = stackalloc byte[HandshakeHash.HashSize];
            var span = new Span<byte>(hash, HandshakeHash.HashSize);
            HandshakeHash.InterimHash(hash, HandshakeHash.HashSize);
            _keySchedule.GenerateHandshakeTrafficKeys(span);
        }

        public void WriteHandshake(ref WritableBuffer writer, HandshakeType handshakeType, Func<WritableBuffer, ConnectionState, WritableBuffer> contentWriter)
        {
            var dataWritten = writer.BytesWritten;
            writer.WriteBigEndian(handshakeType);
            BufferExtensions.WriteVector24Bit(ref writer, contentWriter, this);
            if (HandshakeHash != null)
            {
                var hashBuffer = writer.AsReadableBuffer().Slice(dataWritten);
                HandshakeHash.HashData(hashBuffer);
            }
        }

        public void Dispose()
        {
            HandshakeHash?.Dispose();
            _keySchedule?.Dispose();
            KeyShare?.Dispose();
            ReadKey?.Dispose();
            WriteKey?.Dispose();
            GC.SuppressFinalize(this);
        }

        ~ConnectionState()
        {
            Dispose();
        }
    }
}
