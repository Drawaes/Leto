using Leto.Handshake.Extensions;

namespace Leto
{
    public interface ISecurePipeListener
    {
        ICryptoProvider CryptoProvider { get; }
        ApplicationLayerProtocolProvider AlpnProvider { get; }
        SecureRenegotiationProvider SecureRenegotiationProvider { get; }
        Certificates.CertificateList CertificateList { get; }
        ConnectionStates.SecretSchedules.SecretSchedulePool SecretSchedulePool { get; }
    }
}
