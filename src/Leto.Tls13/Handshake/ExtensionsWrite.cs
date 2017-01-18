using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.IO.Pipelines.Text.Primitives;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Leto.Tls13.Certificates;
using Leto.Tls13.Internal;
using Leto.Tls13.KeyExchange;
using Leto.Tls13.Sessions;
using Leto.Tls13.State;

namespace Leto.Tls13.Handshake
{
    public class ExtensionsWrite
    {
        public static WritableBuffer WriteExtensionList(WritableBuffer buffer, IConnectionStateTls13 connectionState)
        {
            if (connectionState.State == StateType.SendServerHello)
            {
                if (connectionState.PskIdentity != -1)
                {
                    buffer.WriteBigEndian(ExtensionType.pre_shared_key);
                    buffer.WriteBigEndian<ushort>(sizeof(ushort));
                    buffer.WriteBigEndian((ushort)connectionState.PskIdentity);
                }
                if (connectionState.KeyShare != null)
                {
                    WriteServerKeyshare(ref buffer, connectionState);
                }
            }
            if (connectionState.State == StateType.WaitHelloRetry)
            {
                WriteRetryKeyshare(ref buffer, connectionState);
            }
            if (connectionState.State == StateType.SendClientHello)
            {
                WriteSupportedVersion(ref buffer, connectionState);
                WriteClientKeyshares(ref buffer, connectionState);
                WriteSignatureSchemes(ref buffer, connectionState);
                WriteSupportedGroups(ref buffer, connectionState);
            }
            if (connectionState.State == StateType.ServerAuthentication)
            {
                WriteServerEarlyData(ref buffer, connectionState);
            }
            return buffer;
        }

        public static WritableBuffer WriteExtensionListTls12(WritableBuffer buffer, IConnectionState connectionState)
        {

            return buffer;
        }

        public static void WriteSupportedGroups(ref WritableBuffer buffer, IConnectionStateTls13 connectionState)
        {
            buffer.WriteBigEndian(ExtensionType.supported_groups);
            BufferExtensions.WriteVector<ushort>(ref buffer, (writer, state) =>
            {
                connectionState.CryptoProvider.WriteSupportedGroups(ref writer);
                return writer;
            }, connectionState);
        }

        public static void WriteSignatureSchemes(ref WritableBuffer buffer, IConnectionStateTls13 connectionState)
        {
            buffer.WriteBigEndian(ExtensionType.signature_algorithms);
            BufferExtensions.WriteVector<ushort>(ref buffer, (writer, state) =>
            {
                connectionState.CryptoProvider.WriteSignatureSchemes(ref writer);
                return writer;
            }, connectionState);
        }

        public static void WriteServerEarlyData(ref WritableBuffer buffer, IConnectionStateTls13 connectionState)
        {
            if (connectionState.EarlyDataSupported)
            {
                buffer.WriteBigEndian(ExtensionType.early_data);
                buffer.WriteBigEndian<ushort>(0);
            }
        }
        public static void WriteRetryKeyshare(ref WritableBuffer buffer, IConnectionStateTls13 connectionState)
        {
            buffer.WriteBigEndian(ExtensionType.key_share);
            buffer.WriteBigEndian((ushort)sizeof(NamedGroup));
            buffer.WriteBigEndian(connectionState.KeyShare.NamedGroup);
        }

        public static void WriteClientKeyshares(ref WritableBuffer buffer, IConnectionStateTls13 connectionState)
        {
            buffer.WriteBigEndian(ExtensionType.key_share);
            BufferExtensions.WriteVector<ushort>(ref buffer, (innerWriter, innerState) =>
            {
                BufferExtensions.WriteVector<ushort>(ref innerWriter, (writer, state) =>
                {
                    WriteKeyShare(ref writer, state.KeyShare);
                    return writer;
                }, innerState);
                return innerWriter;
            }, connectionState);
        }

        public static void WriteServerKeyshare(ref WritableBuffer buffer, IConnectionState connectionState)
        {
            buffer.WriteBigEndian(ExtensionType.key_share);
            BufferExtensions.WriteVector<ushort>(ref buffer, (writer, state) =>
            {
                WriteKeyShare(ref writer, state.KeyShare);
                return writer;
            }, connectionState);
        }

        public static void WriteKeyShare(ref WritableBuffer buffer, IKeyshareInstance keyshare)
        {
            buffer.WriteBigEndian(keyshare.NamedGroup);
            buffer.WriteBigEndian((ushort)keyshare.KeyExchangeSize);
            keyshare.WritePublicKey(ref buffer);
        }

        public static void WriteServerName(ref WritableBuffer buffer, IConnectionStateTls13 connectionState)
        {
            buffer.WriteBigEndian(ExtensionType.server_name);
            buffer.WriteBigEndian((ushort)(sizeof(ushort) + connectionState.ServerName.Length));
            buffer.WriteBigEndian((ushort)connectionState.ServerName.Length);
            buffer.Write(Encoding.UTF8.GetBytes(connectionState.ServerName));
        }

        public static void WriteSupportedVersion(ref WritableBuffer writer, IConnectionState connectionState)
        {
            writer.WriteBigEndian(ExtensionType.supported_versions);
            writer.WriteBigEndian((ushort)3);
            writer.WriteBigEndian((byte)2);
            writer.WriteBigEndian(connectionState.Version);
        }


    }
}
