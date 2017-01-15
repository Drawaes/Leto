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
    public class ServerConnectionState : IConnectionState
    {
        private Signal _dataForCurrentScheduleSent = new Signal(Signal.ContinuationMode.Synchronous);
        private SecurePipelineListener _listener;
        private IBulkCipherInstance _readKey;
        private IBulkCipherInstance _writeKey;

        public ServerConnectionState(SecurePipelineListener listener)
        {
            State = StateType.None;
            _listener = listener;
            PskKeyExchangeMode = PskKeyExchangeMode.none;
        }

        public SecurePipelineListener Listener => _listener;
        public string ServerName { get; set; }
        public PskKeyExchangeMode PskKeyExchangeMode { get; set; }
        public IKeyshareInstance KeyShare { get; set; }
        public KeySchedule KeySchedule { get; set; }
        public ResumptionProvider ResumptionProvider => _listener.ResumptionProvider;
        public IHashInstance HandshakeHash { get; set; }
        public CryptoProvider CryptoProvider => _listener.CryptoProvider;
        public IBulkCipherInstance ReadKey => _readKey;
        public IBulkCipherInstance WriteKey => _writeKey;
        public CertificateList CertificateList => _listener.CertificateList;
        public CipherSuite CipherSuite { get; set; }
        public StateType State { get; set; }
        public ushort Version { get; set; }
        public ICertificate Certificate { get; set; }
        public Signal DataForCurrentScheduleSent => _dataForCurrentScheduleSent;
        public SignatureScheme SignatureScheme { get; set; }
        public int PskIdentity { get; set; } = -1;
        public IBulkCipherInstance EarlyDataKey { get; set; }
        public bool EarlyDataSupported { get; set; }

        public void StartHandshakeHash(ReadableBuffer readable)
        {
            _dataForCurrentScheduleSent.Set();
            HandshakeHash = CryptoProvider.HashProvider.GetHashInstance(CipherSuite.HashType);
            HandshakeHash.HashData(readable);
        }

        public void HandshakeContext(ReadableBuffer readable)
        {
            HandshakeHash?.HashData(readable);
        }

        public async Task HandleMessage(HandshakeType handshakeMessageType, ReadableBuffer buffer, IPipelineWriter pipe)
        {
            WritableBuffer writer;
            switch (State)
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
                        writer = pipe.Alloc();
                        this.WriteHandshake(ref writer, HandshakeType.hello_retry_request, Hello.SendHelloRetry);
                        await writer.FlushAsync();
                        return;
                    }
                    //Write the server hello, the last of the unencrypted messages
                    State = StateType.SendServerHello;
                    writer = pipe.Alloc();
                    this.WriteHandshake(ref writer, HandshakeType.server_hello, Hello.SendServerHello);
                    //block our next actions because we need to have sent the message before changing keys
                    _dataForCurrentScheduleSent.Reset();
                    await writer.FlushAsync();
                    await _dataForCurrentScheduleSent;
                    State = StateType.ServerAuthentication;
                    //Generate the encryption keys and send the next set of messages
                    GenerateHandshakeKeys();
                    writer = pipe.Alloc();
                    ServerHandshake.SendFlightOne(ref writer, this);
                    ServerHandshake.ServerFinished(ref writer, this, KeySchedule.GenerateServerFinishKey());
                    await writer.FlushAsync();
                    if (EarlyDataSupported && EarlyDataKey != null && PskIdentity != -1)
                    {
                        State = StateType.WaitEarlyDataFinished;
                    }
                    else
                    {
                        State = StateType.WaitClientFinished;
                    }
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
                    this.WriteHandshake(ref writer, HandshakeType.new_session_ticket, SessionKeys.CreateNewSessionKey);
                    await writer.FlushAsync();
                    State = StateType.HandshakeComplete;
                    break;
                default:
                    Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.unexpected_message);
                    break;
            }
        }

        private bool NegotiationComplete()
        {
            if (PskIdentity != -1)
            {
                return true;
            }
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
            KeySchedule.GenerateMasterSecret(span, ref _readKey, ref _writeKey);
        }

        private unsafe void GenerateHandshakeKeys()
        {
            if (KeySchedule == null)
            {
                KeySchedule = _listener.KeyScheduleProvider.GetKeySchedule(this, null);
            }
            KeySchedule.SetDheDerivedValue(KeyShare);
            var hash = stackalloc byte[HandshakeHash.HashSize];
            var span = new Span<byte>(hash, HandshakeHash.HashSize);
            HandshakeHash.InterimHash(hash, HandshakeHash.HashSize);
            KeySchedule.GenerateHandshakeTrafficKeys(span, ref _readKey, ref _writeKey);
            if (EarlyDataKey != null && PskIdentity != -1 && EarlyDataSupported)
            {
                _readKey.Dispose();
                _readKey = EarlyDataKey;
            }
                       
        }

        public void Dispose()
        {
            HandshakeHash?.Dispose();
            KeySchedule?.Dispose();
            KeyShare?.Dispose();
            ReadKey?.Dispose();
            WriteKey?.Dispose();
            GC.SuppressFinalize(this);
        }

        public void StartHandshake(ref WritableBuffer writer)
        {
        }

        ~ServerConnectionState()
        {
            Dispose();
        }
    }
}
