package pcap

const (
	TLS_HANDSHAKE          = 0x16
	TLS_CHANGE_CIPHER_SPEC = 0x14
	TLS_APPLICATION_DATA   = 0x17
)

const (
	TLS_HANDSHAKE_CLIENT_HELLO        = 0x01
	TLS_HANDSHAKE_SERVER_HELLO        = 0x02
	TLS_HANDSHAKE_CERTIFICATE         = 0x0b
	TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE = 0x10
	TLS_HANDSHAKE_ALERT               = 0x15
)
const (
	TLS_ALERT_TYPE_WARNING = 0x1
	TLS_ALERT_TYPE_FATAL   = 0x2
)

const (
	// Warning alerts
	TLS_ALERT_LEVEL_CLOSE_NOTIFY     = 0x00 // close_notify
	TLS_ALERT_LEVEL_USER_CANCELED    = 0x0a // user_canceled
	TLS_ALERT_LEVEL_NO_RENEGOTIATION = 0x64 // no_renegotiation

	// Fatal alerts
	TLS_ALERT_LEVEL_UNEXPECTED_MESSAGE              = 0x10 // unexpected_message
	TLS_ALERT_LEVEL_BAD_RECORD_MAC                  = 0x14 // bad_record_mac
	TLS_ALERT_LEVEL_DECRYPTION_FAILED               = 0x15 // decryption_failed
	TLS_ALERT_LEVEL_RECORD_OVERFLOW                 = 0x16 // record_overflow
	TLS_ALERT_LEVEL_DECOMPRESSION_FAILURE           = 0x1e // decompression_failure
	TLS_ALERT_LEVEL_HANDSHAKE_FAILURE               = 0x28 // handshake_failure
	TLS_ALERT_LEVEL_NO_CERTIFICATE                  = 0x29 // no_certificate
	TLS_ALERT_LEVEL_BAD_CERTIFICATE                 = 0x2a // bad_certificate
	TLS_ALERT_LEVEL_UNSUPPORTED_CERTIFICATE         = 0x2b // unsupported_certificate
	TLS_ALERT_LEVEL_CERTIFICATE_REVOKED             = 0x2c // certificate_revoked
	TLS_ALERT_LEVEL_CERTIFICATE_EXPIRED             = 0x2d // certificate_expired
	TLS_ALERT_LEVEL_CERTIFICATE_UNKNOWN             = 0x2e // certificate_unknown
	TLS_ALERT_LEVEL_ILLEGAL_PARAMETER               = 0x2f // illegal_parameter
	TLS_ALERT_LEVEL_UNKNOWN_CA                      = 0x30 // unknown_ca
	TLS_ALERT_LEVEL_ACCESS_DENIED                   = 0x31 // access_denied
	TLS_ALERT_LEVEL_DECODE_ERROR                    = 0x32 // decode_error
	TLS_ALERT_LEVEL_DECRYPT_ERROR                   = 0x33 // decrypt_error
	TLS_ALERT_LEVEL_EXPORT_RESTRICTION              = 0x3c // export_restriction
	TLS_ALERT_LEVEL_PROTOCOL_VERSION                = 0x46 // protocol_version
	TLS_ALERT_LEVEL_INSUFFICIENT_SECURITY           = 0x47 // insufficient_security
	TLS_ALERT_LEVEL_INTERNAL_ERROR                  = 0x50 // internal_error
	TLS_ALERT_LEVEL_INAPPROPRIATE_FALLBACK          = 0x56 // inappropriate_fallback
	TLS_ALERT_LEVEL_UNRECOGNIZED_NAME               = 0x70 // unrecognized_name
	TLS_ALERT_LEVEL_BAD_CERTIFICATE_STATUS_RESPONSE = 0x71 // bad_certificate_status_response
	TLS_ALERT_LEVEL_BAD_CERTIFICATE_HASH_VALUE      = 0x72 // bad_certificate_hash_value
	TLS_ALERT_LEVEL_UNKNOWN_PSK_IDENTITY            = 0x73 // unknown_psk_identity
)
