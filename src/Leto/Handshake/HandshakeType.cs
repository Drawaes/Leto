namespace Leto.Handshake
{
    public enum HandshakeType : byte
    {
        none = 0,
        client_hello = 1,
        server_hello = 2,
        new_session_ticket = 4,
        end_of_early_data = 5,
        hello_retry_request = 6,
        encrypted_extensions = 8,
        certificate = 11,
        server_key_exchange = 12,
        certificate_request = 13,
        server_hello_done = 14,
        certificate_verify = 15,
        client_key_exchange = 16,
        finished = 20,
        key_update = 24,
    }
}
