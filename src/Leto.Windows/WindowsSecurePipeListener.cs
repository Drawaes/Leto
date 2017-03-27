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

        public WindowsSecurePipeListener(ICertificate certificate, PipeFactory pipeFactory = null)
            :base(certificate, pipeFactory)
        {
            _cryptoProvider = new WindowsCryptoProvider();
        }

        public override ICryptoProvider CryptoProvider => _cryptoProvider;
        public override ISessionProvider SessionProvider => null;

        protected override void Dispose(bool disposing)
        {
            _cryptoProvider.Dispose();
            base.Dispose(disposing);
        }
    }
}
