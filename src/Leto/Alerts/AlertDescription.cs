namespace Leto.Alerts
{
    //http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
    //http://www.iana.org/go/rfc5246
    public enum AlertDescription : byte
    {
        close_notify = 0,
        end_of_early_data = 1,
        unexpected_message = 10,
        bad_record_mac = 20,
        decryption_failed_RESERVED = 21,
        record_overflow = 22,
        decompression_failure_RESERVED = 30,
        handshake_failure = 40,
        no_certificate_RESERVED = 41,
        bad_certificate = 42,
        unsupported_certificate = 43,
        certificate_revoked = 44,
        certificate_expired = 45,
        certificate_unknown = 46,
        illegal_parameter = 47,
        unknown_ca = 48,
        access_denied = 49,
        decode_error = 50,
        decrypt_error = 51,
        export_restriction_RESERVED = 60,
        protocol_version = 70,
        insufficient_security = 71,
        internal_error = 80,
        inappropriate_fallback = 86,
        user_canceled = 90,
        no_renegotiation_RESERVED = 100,
        missing_extension = 109,
        unsupported_extension = 110,
        certificate_unobtainable = 111,
        unrecognized_name = 112,
        bad_certificate_status_response = 113,
        bad_certificate_hash_value = 114,
        unknown_psk_identity = 115,
        certificate_required = 116,
    }
}
