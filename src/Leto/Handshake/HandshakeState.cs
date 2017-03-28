namespace Leto.Handshake
{
    public enum HandshakeState
    {
        WaitingForClientKeyExchange,
        WaitingForChangeCipherSpec,
        WaitingForClientFinished,
        HandshakeCompleted,
        WaitingForClientFinishedAbbreviated
    }
}
