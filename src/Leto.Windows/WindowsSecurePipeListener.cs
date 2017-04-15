using System;
using System.Collections.Generic;
using System.Text;
using Leto.Certificates;
using Leto.ConnectionStates.SecretSchedules;
using Leto.Handshake.Extensions;
using System.Threading.Tasks;
using System.IO.Pipelines;
using Leto.Sessions;

namespace Leto.Windows
{
    public sealed class WindowsSecurePipeListener : SecurePipeListener
    {
        private WindowsCryptoProvider _cryptoProvider;
        private ISessionProvider _sessionProvider;
        
        public WindowsSecurePipeListener(ICertificate certificate, PipeFactory pipeFactory = null)
            :base(certificate, pipeFactory)
        {
            _sessionProvider = new Sessions.EphemeralSessionProvider();
            _cryptoProvider = new WindowsCryptoProvider();
        }

        public override ICryptoProvider CryptoProvider => _cryptoProvider;
        public override ISessionProvider SessionProvider => _sessionProvider;

        protected override void Dispose(bool disposing)
        {
            _sessionProvider?.Dispose();
            _cryptoProvider.Dispose();
            base.Dispose(disposing);
        }
    }
}
