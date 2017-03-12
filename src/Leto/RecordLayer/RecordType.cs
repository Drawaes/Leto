namespace Leto.RecordLayer
{
    public enum RecordType : byte
    {
        ChangeCipherSpec = 0x14,
        Alert = 0x15,
        Handshake = 0x16,
        Application = 0x17,
    }
}
