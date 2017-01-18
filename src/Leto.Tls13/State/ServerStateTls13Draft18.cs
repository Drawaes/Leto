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
    public class ServerStateTls13Draft18 : IConnectionStateTls13
    {
        private Signal _dataForCurrentScheduleSent = new Signal(Signal.ContinuationMode.Synchronous);
        private SecurePipelineListener _listener;
        private IBulkCipherInstance _readKey;
        private IBulkCipherInstance _writeKey;
        private StateType _state;

        public ServerStateTls13Draft18(SecurePipelineListener listener)
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
        public StateType State
        {
            get { return _state;}
            set
            {
                Console.WriteLine($"State changed {_state}");
                _state = value;
            }
        }
        public TlsVersion Version => TlsVersion.Tls13Draft18;
        public ICertificate Certificate { get; set; }
        public Signal DataForCurrentScheduleSent => _dataForCurrentScheduleSent;
        public SignatureScheme SignatureScheme { get; set; }
        public int PskIdentity { get; set; } = -1;
        public bool EarlyDataSupported { get; set; }
        
        public void HandshakeContext(ReadableBuffer readable)
        {
            HandshakeHash?.HashData(readable);
        }

        public async Task HandleHandshakeMessage(HandshakeType handshakeMessageType, ReadableBuffer buffer, IPipelineWriter pipe)
        {
            WritableBuffer writer;
            switch (State)
            {
                case StateType.None:
                case StateType.WaitHelloRetry:
                    if (handshakeMessageType != HandshakeType.client_hello)
                    {
                        Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.unexpected_message, $"State is wait hello retry but got {handshakeMessageType}");
                    }
                    Hello.ReadClientHelloTls13(buffer, this);
                    if (CipherSuite == null)
                    {
                        //Couldn't agree a set of ciphers
                        Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure, "Could not agree on a cipher suite during reading client hello");
                    }
                    this.StartHandshakeHash(buffer);
                    //If we can't agree on a schedule we will have to send a hello retry and try again
                    if (!NegotiationComplete())
                    {
                        writer = pipe.Alloc();
                        this.WriteHandshake(ref writer, HandshakeType.hello_retry_request, Hello.SendHelloRetry);
                        State = StateType.WaitHelloRetry;
                        await writer.FlushAsync();
                        return;
                    }
                    if (PskIdentity != -1 && EarlyDataSupported)
                    {
                        KeySchedule.GenerateEarlyTrafficKey(ref _readKey);
                        Console.WriteLine("Generated Early Traffic Key");
                    }
                    //Write the server hello, the last of the unencrypted messages
                    State = StateType.SendServerHello;
                    writer = pipe.Alloc();
                    this.WriteHandshake(ref writer, HandshakeType.server_hello, Hello.SendServerHello13);
                    //block our next actions because we need to have sent the message before changing keys
                    _dataForCurrentScheduleSent.Reset();
                    await writer.FlushAsync();
                    await _dataForCurrentScheduleSent;
                    State = StateType.ServerAuthentication;
                    //Generate the encryption keys and send the next set of messages
                    GenerateHandshakeKeys();
                    writer = pipe.Alloc();
                    ServerHandshake.SendFlightOne(ref writer, this);
                    _dataForCurrentScheduleSent.Reset();
                    await writer.FlushAsync();
                    await _dataForCurrentScheduleSent;
                    writer = pipe.Alloc();
                    ServerHandshake.SendFlightOne2(ref writer, this);
                    _dataForCurrentScheduleSent.Reset();
                    await writer.FlushAsync();
                    await _dataForCurrentScheduleSent;
                    writer = pipe.Alloc();
                    ServerHandshake.SendFlightOne3(ref writer, this);
                    ServerHandshake.ServerFinished(ref writer, this, KeySchedule.GenerateServerFinishKey());
                    _dataForCurrentScheduleSent.Reset();
                    await writer.FlushAsync();
                    await _dataForCurrentScheduleSent;
                    GenerateServerApplicationKey();
                    if (EarlyDataSupported && PskIdentity != -1)
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
                        Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.unexpected_message, $"Waiting for client finished but received {handshakeMessageType}");
                    }
                    Finished.ReadClientFinished(buffer, this);
                    _readKey?.Dispose();
                    _readKey = KeySchedule.GenerateClientApplicationKey();
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
                    Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.unexpected_message,$"Not in any known state {State} that we expected a handshake messge from {handshakeMessageType}" );
                    break;
            }
        }

        public void HandleAlertMessage(ReadableBuffer messageBuffer)
        {
            var level = messageBuffer.ReadBigEndian<Alerts.AlertLevel>();
            messageBuffer = messageBuffer.Slice(sizeof(Alerts.AlertLevel));
            var description = messageBuffer.ReadBigEndian<Alerts.AlertDescription>();
            if (level == Alerts.AlertLevel.Warning && description == Alerts.AlertDescription.end_of_early_data && State == StateType.WaitEarlyDataFinished)
            {
                //0RTT data finished so we switch the reader key to the handshake key and wait for 
                //the client to send it's finish message
                _readKey?.Dispose();
                _readKey = KeySchedule.GenerateClientHandshakeKey();
                State = StateType.WaitClientFinished;
                return;
            }
            Alerts.AlertException.ThrowAlert(level, description,"Alert from the client");
        }

        private bool NegotiationComplete()
        {
            if (PskIdentity != -1)
            {
                return true;
            }
            if (KeyShare == null || Certificate == null)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.illegal_parameter,$"negotiation complete but no cipher suite or certificate");
            }
            if (!KeyShare.HasPeerKey)
            {
                return false;
            }
            return true;
        }

        private unsafe void GenerateServerApplicationKey()
        {
            var hash = stackalloc byte[HandshakeHash.HashSize];
            var span = new Span<byte>(hash, HandshakeHash.HashSize);
            HandshakeHash.InterimHash(hash, HandshakeHash.HashSize);
            KeySchedule.GenerateMasterSecret(span);
            Console.WriteLine("Application Write Key");
            _writeKey?.Dispose();
            _writeKey = KeySchedule.GenerateServerApplicationKey();
        }

        private unsafe void GenerateHandshakeKeys()
        {
            if (KeySchedule == null)
            {
                KeySchedule = Listener.KeyScheduleProvider.GetKeySchedule(this);
            }
            KeySchedule.SetDheDerivedValue(KeyShare);
            var hash = stackalloc byte[HandshakeHash.HashSize];
            var span = new Span<byte>(hash, HandshakeHash.HashSize);
            HandshakeHash.InterimHash(hash, HandshakeHash.HashSize);
            KeySchedule.GenerateHandshakeTrafficSecrets(span);
            Console.WriteLine("Handshake Write Key");
            _writeKey = KeySchedule.GenerateServerHandshakeKey();
            if (PskIdentity == -1 || !EarlyDataSupported)
            {
                _readKey?.Dispose();
                _readKey = KeySchedule.GenerateClientHandshakeKey();
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

        ~ServerStateTls13Draft18()
        {
            Dispose();
        }
    }
}
