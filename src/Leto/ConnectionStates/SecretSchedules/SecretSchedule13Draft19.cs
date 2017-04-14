using System;
using System.Collections.Generic;
using System.Text;
using Leto.BulkCiphers;
using static Leto.TlsConstants.Tls13;

namespace Leto.ConnectionStates.SecretSchedules
{
    public class SecretSchedule13Draft19 : SecretSchedule13
    {
        public override (AeadBulkCipher clientKey, AeadBulkCipher serverKey) GenerateHandshakeKeys()
        {
            ExpandLabel(_secret, Label_DerivedSecret, new Span<byte>(), _secret);
            return base.GenerateHandshakeKeys();
        }
    }
}
