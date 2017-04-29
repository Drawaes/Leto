using System;
using System.Collections.Generic;
using System.Text;
using Leto.Handshake.Extensions;
using Leto.Certificates;
using Leto.ConnectionStates.SecretSchedules;
using System.IO.Pipelines;
using System.Threading.Tasks;
using Leto.Sessions;

namespace Leto.OpenSsl11
{
    public sealed class OpenSslSecurePipeListener : SecurePipeListener
    {
        private ISessionProvider _sessionProvider;

        public OpenSslSecurePipeListener(ICertificate certificate, PipeFactory pipeFactory = null)
            : base(certificate, pipeFactory) => CryptoProvider = new OpenSslCryptoProviderImpl();

        public override ICryptoProvider CryptoProvider { get; set; }
        public override ISessionProvider SessionProvider => _sessionProvider;

        public void UseSessionProvider(ISessionProvider sessionProvider) => _sessionProvider = sessionProvider;

        public void UseEphemeralSessionProvider()
        {
            var provider = new Sessions.EphemeralSessionProvider(CryptoProvider, BulkCiphers.BulkCipherType.AES_256_GCM, SecretSchedulePool);
            UseSessionProvider(provider);
        }
    }
}
