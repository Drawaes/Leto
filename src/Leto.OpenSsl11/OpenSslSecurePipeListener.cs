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
        private ICryptoProvider _cryptoProvider;
        private ISessionProvider _sessionProvider;

        public OpenSslSecurePipeListener(ICertificate certificate, PipeFactory pipeFactory = null)
            : base(certificate, pipeFactory) => _cryptoProvider = new OpenSslCryptoProvider();

        public override ICryptoProvider CryptoProvider => _cryptoProvider;
        public override ISessionProvider SessionProvider => _sessionProvider;

        public void UseSessionProvider(ISessionProvider sessionProvider) => _sessionProvider = sessionProvider;

        public void UseEphemeralSessionProvider()
        {
            var provider = new Sessions.EphemeralSessionProvider(_cryptoProvider, BulkCiphers.BulkCipherType.AES_256_GCM, SecretSchedulePool);
            UseSessionProvider(provider);
        }
    }
}
