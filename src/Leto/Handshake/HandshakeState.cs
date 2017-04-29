namespace Leto.Handshake
{
    public enum HandshakeState
    {
        WaitingForClientHello,
        WaitingForClientKeyExchange,
        WaitingForChangeCipherSpec,
        WaitingForClientFinished,
        HandshakeCompleted,
        WaitingForClientFinishedAbbreviated,
        WaitingHelloRetry
    }
}
