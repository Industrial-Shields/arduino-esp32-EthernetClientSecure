#include "EthernetClientSecure.h"

#include <Dns.h>
#include <esp32-hal-log.h>
#include <mbedtls/sha256.h>
#include <mbedtls/oid.h>
#include <algorithm>
#include <string>

EthernetClientSecure::EthernetClientSecure()
{
	_connected = false;

    sslclient = new sslclient_context;
    ssl_init(sslclient);
    sslclient->client = this;
    sslclient->handshake_timeout = 120000;
    _use_insecure = false;
    _CA_cert = NULL;
    _cert = NULL;
    _private_key = NULL;
    _pskIdent = NULL;
    _psKey = NULL;
}

EthernetClientSecure::EthernetClientSecure(int sock) : EthernetClient(sock)
{
	_connected = false;
    _timeout = 0;

    sslclient = new sslclient_context;
    ssl_init(sslclient);
    sslclient->client = this;
    sslclient->handshake_timeout = 120000;

	if ((sock >= 0) && (sock < MAX_SOCK_NUM)) {
		_connected = true;
	}

    _CA_cert = NULL;
    _cert = NULL;
    _private_key = NULL;
    _pskIdent = NULL;
    _psKey = NULL;
}

EthernetClientSecure::~EthernetClientSecure()
{
    stop();
    delete sslclient;
}

void EthernetClientSecure::stop()
{
    if ((getSocketNumber() >= 0) && (getSocketNumber() < MAX_SOCK_NUM)) {
		_connected = false;
        _peek = -1;
    }
    stop_ssl_socket(sslclient, _CA_cert, _cert, _private_key);
}

int EthernetClientSecure::connect(IPAddress ip, uint16_t port)
{
    if (_pskIdent && _psKey)
        return connect(ip, port, _pskIdent, _psKey);
    return connect(ip, port, _CA_cert, _cert, _private_key);
}

int EthernetClientSecure::connect(IPAddress ip, uint16_t port, int32_t timeout){
    _timeout = timeout;
    return connect(ip, port);
}

int EthernetClientSecure::connect(const char *host, uint16_t port)
{
    if (_pskIdent && _psKey)
        return connect(host, port, _pskIdent, _psKey);
    return connect(host, port, _CA_cert, _cert, _private_key);
}

int EthernetClientSecure::connect(const char *host, uint16_t port, int32_t timeout){
    _timeout = timeout;
    return connect(host, port);
}

int EthernetClientSecure::connect(IPAddress ip, uint16_t port, const char *CA_cert, const char *cert, const char *private_key)
{
    return connect(ip.toString().c_str(), port, CA_cert, cert, private_key);
}

int EthernetClientSecure::connect(const char *host, uint16_t port, const char *CA_cert, const char *cert, const char *private_key)
{
    if(_timeout > 0){
        sslclient->handshake_timeout = _timeout;
    }
    int ret = start_ssl_client(sslclient, host, port, _timeout, CA_cert, cert, private_key, NULL, NULL, _use_insecure);
    _lastError = ret;
    if (ret < 0) {
        log_e("start_ssl_client: %d", ret);
        stop();
        return 0;
    }
	_connected = true;
    return 1;
}

int EthernetClientSecure::connect(IPAddress ip, uint16_t port, const char *pskIdent, const char *psKey) {
    return connect(ip.toString().c_str(), port, pskIdent, psKey);
}

int EthernetClientSecure::connect(const char *host, uint16_t port, const char *pskIdent, const char *psKey) {
    log_v("start_ssl_client with PSK");
    if(_timeout > 0){
        sslclient->handshake_timeout = _timeout;
    }
    int ret = start_ssl_client(sslclient, host, port, _timeout, NULL, NULL, NULL, pskIdent, psKey, _use_insecure);
    _lastError = ret;
    if (ret < 0) {
        log_e("start_ssl_client: %d", ret);
        stop();
        return 0;
    }
	_connected = true;
    return 1;
}

int EthernetClientSecure::connect_(IPAddress ip, uint16_t port) {
	log_v("connect_");
	return EthernetClient::connect(ip, port);
}

int EthernetClientSecure::peek(){
    if(_peek >= 0){
        return _peek;
    }
    _peek = timedRead();
    return _peek;
}

size_t EthernetClientSecure::write(uint8_t data)
{
    return write(&data, 1);
}

int EthernetClientSecure::read()
{
    uint8_t data = -1;
    int res = read(&data, 1);
    if (res < 0) {
        return res;
    }
    return data;
}

size_t EthernetClientSecure::write(const uint8_t *buf, size_t size)
{
	if (!_connected) {
		return 0;
	}
    int res = send_ssl_data(sslclient, buf, size);
    if (res < 0) {
        stop();
        res = 0;
    }
    return res;
}

int EthernetClientSecure::write_(const uint8_t* buf, size_t size) {
	log_v("write_: %d", size);
	return EthernetClient::write(buf, size);
}

int EthernetClientSecure::read(uint8_t *buf, size_t size)
{
    int peeked = 0;
    int avail = available();
    if ((!buf && size) || avail <= 0) {
        return -1;
    }
    if(!size){
        return 0;
    }
    if(_peek >= 0){
        buf[0] = _peek;
        _peek = -1;
        size--;
        avail--;
        if(!size || !avail){
            return 1;
        }
        buf++;
        peeked = 1;
    }

    int res = get_ssl_receive(sslclient, buf, size);
    if (res < 0) {
        stop();
        return peeked?peeked:res;
    }
    return res + peeked;
}

int EthernetClientSecure::read_(uint8_t* buf, size_t size) {
	log_v("read_: %d", size);
	return EthernetClient::read(buf, size);
}

int EthernetClientSecure::available()
{
    int peeked = (_peek >= 0);
	if (!_connected) {
		return peeked;
	}
    int res = data_to_read(sslclient);
    if (res < 0) {
        stop();
        return peeked?peeked:res;
    }
    return res+peeked;
}

uint8_t EthernetClientSecure::connected() {
	uint8_t dummy = 0;
	read(&dummy, 0);
	return _connected;
}

void EthernetClientSecure::setInsecure()
{
    _CA_cert = NULL;
    _cert = NULL;
    _private_key = NULL;
    _pskIdent = NULL;
    _psKey = NULL;
    _use_insecure = true;
}

void EthernetClientSecure::setCACert (const char *rootCA)
{
    _CA_cert = rootCA;
}

void EthernetClientSecure::setCertificate (const char *client_ca)
{
    _cert = client_ca;
}

void EthernetClientSecure::setPrivateKey (const char *private_key)
{
    _private_key = private_key;
}

void EthernetClientSecure::setPreSharedKey(const char *pskIdent, const char *psKey) {
    _pskIdent = pskIdent;
    _psKey = psKey;
}

bool EthernetClientSecure::verify(const char* fp, const char* domain_name)
{
    if (!sslclient)
        return false;

    return verify_ssl_fingerprint(sslclient, fp, domain_name);
}

char *EthernetClientSecure::_streamLoad(Stream& stream, size_t size) {
  char *dest = (char*)malloc(size+1);
  if (!dest) {
    return nullptr;
  }
  if (size != stream.readBytes(dest, size)) {
    free(dest);
    dest = nullptr;
    return nullptr;
  }
  dest[size] = '\0';
  return dest;
}

bool EthernetClientSecure::loadCACert(Stream& stream, size_t size) {
  char *dest = _streamLoad(stream, size);
  bool ret = false;
  if (dest) {
    setCACert(dest);
    ret = true;
  }
  return ret;
}

bool EthernetClientSecure::loadCertificate(Stream& stream, size_t size) {
  char *dest = _streamLoad(stream, size);
  bool ret = false;
  if (dest) {
    setCertificate(dest);
    ret = true;
  }
  return ret;
}

bool EthernetClientSecure::loadPrivateKey(Stream& stream, size_t size) {
  char *dest = _streamLoad(stream, size);
  bool ret = false;
  if (dest) {
    setPrivateKey(dest);
    ret = true;
  }
  return ret;
}

int EthernetClientSecure::lastError(char *buf, const size_t size)
{
    if (!_lastError) {
        return 0;
    }
    mbedtls_strerror(_lastError, buf, size);
    return _lastError;
}

void EthernetClientSecure::setHandshakeTimeout(unsigned long handshake_timeout)
{
    sslclient->handshake_timeout = handshake_timeout * 1000;
}

#ifndef MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED
#  warning "Please configure IDF framework to include mbedTLS -> Enable pre-shared-key ciphersuites and activate at least one cipher"
#else

const char *pers = "esp32-tls";

static int _handle_error(int err, const char * function, int line)
{
    if(err == -30848){
        return err;
    }
#ifdef MBEDTLS_ERROR_C
    char error_buf[100];
    mbedtls_strerror(err, error_buf, 100);
    log_e("[%s():%d]: (%d) %s", function, line, err, error_buf);
#else
    log_e("[%s():%d]: code %d", function, line, err);
#endif
    return err;
}

#define handle_error(e) _handle_error(e, __FUNCTION__, __LINE__)

int ssl_client_send(void* ctx, const unsigned char* buf, size_t len) {
	EthernetClientSecure* client = (EthernetClientSecure*) ctx;
	if (!client) {
		return 0;
	}
	return client->write_(buf, len);
}

int ssl_client_receive(void* ctx, unsigned char* buf, size_t len) {
	EthernetClientSecure* client = (EthernetClientSecure*) ctx;
	if (!client) {
		return 0;
	}
	int ret = client->read_(buf, len);
	if (ret < 0) {
		return MBEDTLS_ERR_SSL_WANT_READ;
	}
	return ret;
}

void ssl_init(sslclient_context *ssl_client)
{
    mbedtls_ssl_init(&ssl_client->ssl_ctx);
    mbedtls_ssl_config_init(&ssl_client->ssl_conf);
    mbedtls_ctr_drbg_init(&ssl_client->drbg_ctx);
}


int start_ssl_client(sslclient_context *ssl_client, const char *host, uint32_t port, int timeout, const char *rootCABuff, const char *cli_cert, const char *cli_key, const char *pskIdent, const char *psKey, bool insecure)
{
    char buf[512];
    int ret, flags;
    int enable = 1;
    log_v("Free internal heap before TLS %u", ESP.getFreeHeap());

    if (rootCABuff == NULL && pskIdent == NULL && psKey == NULL && !insecure) {
        return -1;
    }

	if (ssl_client->client == NULL) {
		return -1;
	}

	DNSClient dns; // Look up the host first
	IPAddress remote_addr;
	dns.begin(Ethernet.dnsServerIP());
	if (!dns.getHostByName(host, remote_addr)) return 0; // TODO: use _timeout

    log_v("Starting connection");
	
	if (!ssl_client->client->connect_(remote_addr, port)) {
		return -1;
	}

    log_v("Seeding the random number generator");
    mbedtls_entropy_init(&ssl_client->entropy_ctx);

    ret = mbedtls_ctr_drbg_seed(&ssl_client->drbg_ctx, mbedtls_entropy_func,
                                &ssl_client->entropy_ctx, (const unsigned char *) pers, strlen(pers));
    if (ret < 0) {
        return handle_error(ret);
    }

    log_v("Setting up the SSL/TLS structure...");

    if ((ret = mbedtls_ssl_config_defaults(&ssl_client->ssl_conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        return handle_error(ret);
    }

    // MBEDTLS_SSL_VERIFY_REQUIRED if a CA certificate is defined on Arduino IDE and
    // MBEDTLS_SSL_VERIFY_NONE if not.

    if (insecure) {
        mbedtls_ssl_conf_authmode(&ssl_client->ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
        log_i("WARNING: Skipping SSL Verification. INSECURE!");
    } else if (rootCABuff != NULL) {
        log_v("Loading CA cert");
        mbedtls_x509_crt_init(&ssl_client->ca_cert);
        mbedtls_ssl_conf_authmode(&ssl_client->ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        ret = mbedtls_x509_crt_parse(&ssl_client->ca_cert, (const unsigned char *)rootCABuff, strlen(rootCABuff) + 1);
        mbedtls_ssl_conf_ca_chain(&ssl_client->ssl_conf, &ssl_client->ca_cert, NULL);
        //mbedtls_ssl_conf_verify(&ssl_client->ssl_ctx, my_verify, NULL );
        if (ret < 0) {
            // free the ca_cert in the case parse failed, otherwise, the old ca_cert still in the heap memory, that lead to "out of memory" crash.
            mbedtls_x509_crt_free(&ssl_client->ca_cert);
            return handle_error(ret);
        }
    } else if (pskIdent != NULL && psKey != NULL) {
        log_v("Setting up PSK");
        // convert PSK from hex to binary
        if ((strlen(psKey) & 1) != 0 || strlen(psKey) > 2*MBEDTLS_PSK_MAX_LEN) {
            log_e("pre-shared key not valid hex or too long");
            return -1;
        }
        unsigned char psk[MBEDTLS_PSK_MAX_LEN];
        size_t psk_len = strlen(psKey)/2;
        for (int j=0; j<strlen(psKey); j+= 2) {
            char c = psKey[j];
            if (c >= '0' && c <= '9') c -= '0';
            else if (c >= 'A' && c <= 'F') c -= 'A' - 10;
            else if (c >= 'a' && c <= 'f') c -= 'a' - 10;
            else return -1;
            psk[j/2] = c<<4;
            c = psKey[j+1];
            if (c >= '0' && c <= '9') c -= '0';
            else if (c >= 'A' && c <= 'F') c -= 'A' - 10;
            else if (c >= 'a' && c <= 'f') c -= 'a' - 10;
            else return -1;
            psk[j/2] |= c;
        }
        // set mbedtls config
        ret = mbedtls_ssl_conf_psk(&ssl_client->ssl_conf, psk, psk_len,
                 (const unsigned char *)pskIdent, strlen(pskIdent));
        if (ret != 0) {
            log_e("mbedtls_ssl_conf_psk returned %d", ret);
            return handle_error(ret);
        }
    } else {
        return -1;
    }

    if (!insecure && cli_cert != NULL && cli_key != NULL) {
        mbedtls_x509_crt_init(&ssl_client->client_cert);
        mbedtls_pk_init(&ssl_client->client_key);

        log_v("Loading CRT cert");

        ret = mbedtls_x509_crt_parse(&ssl_client->client_cert, (const unsigned char *)cli_cert, strlen(cli_cert) + 1);
        if (ret < 0) {
        // free the client_cert in the case parse failed, otherwise, the old client_cert still in the heap memory, that lead to "out of memory" crash.
        mbedtls_x509_crt_free(&ssl_client->client_cert);
            return handle_error(ret);
        }

        log_v("Loading private key");
        ret = mbedtls_pk_parse_key(&ssl_client->client_key, (const unsigned char *)cli_key, strlen(cli_key) + 1, NULL, 0);

        if (ret != 0) {
            return handle_error(ret);
        }

        mbedtls_ssl_conf_own_cert(&ssl_client->ssl_conf, &ssl_client->client_cert, &ssl_client->client_key);
    }

    log_v("Setting hostname for TLS session...");

    // Hostname set here should match CN in server certificate
    if((ret = mbedtls_ssl_set_hostname(&ssl_client->ssl_ctx, host)) != 0){
        return handle_error(ret);
	}

    mbedtls_ssl_conf_rng(&ssl_client->ssl_conf, mbedtls_ctr_drbg_random, &ssl_client->drbg_ctx);

    if ((ret = mbedtls_ssl_setup(&ssl_client->ssl_ctx, &ssl_client->ssl_conf)) != 0) {
        return handle_error(ret);
    }

    mbedtls_ssl_set_bio(&ssl_client->ssl_ctx, ssl_client->client, ssl_client_send, ssl_client_receive, NULL );

    log_v("Performing the SSL/TLS handshake...");
    unsigned long handshake_start_time=millis();
    while ((ret = mbedtls_ssl_handshake(&ssl_client->ssl_ctx)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            return handle_error(ret);
        }
        if((millis()-handshake_start_time)>ssl_client->handshake_timeout)
			return -1;
	    vTaskDelay(2);//2 ticks
    }


    if (cli_cert != NULL && cli_key != NULL) {
        log_d("Protocol is %s Ciphersuite is %s", mbedtls_ssl_get_version(&ssl_client->ssl_ctx), mbedtls_ssl_get_ciphersuite(&ssl_client->ssl_ctx));
        if ((ret = mbedtls_ssl_get_record_expansion(&ssl_client->ssl_ctx)) >= 0) {
            log_d("Record expansion is %d", ret);
        } else {
            log_w("Record expansion is unknown (compression)");
        }
    }

    log_v("Verifying peer X.509 certificate...");

    if ((flags = mbedtls_ssl_get_verify_result(&ssl_client->ssl_ctx)) != 0) {
        memset(buf, 0, sizeof(buf));
        mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
        log_e("Failed to verify peer certificate! verification info: %s", buf);
        stop_ssl_socket(ssl_client, rootCABuff, cli_cert, cli_key);  //It's not safe continue.
        return handle_error(ret);
    } else {
        log_v("Certificate verified.");
    }

    if (rootCABuff != NULL) {
        mbedtls_x509_crt_free(&ssl_client->ca_cert);
    }

    if (cli_cert != NULL) {
        mbedtls_x509_crt_free(&ssl_client->client_cert);
    }

    if (cli_key != NULL) {
        mbedtls_pk_free(&ssl_client->client_key);
    }

    log_v("Free internal heap after TLS %u", ESP.getFreeHeap());

    return ssl_client->client->getSocketNumber();
}


void stop_ssl_socket(sslclient_context *ssl_client, const char *rootCABuff, const char *cli_cert, const char *cli_key)
{
    log_v("Cleaning SSL connection.");

    mbedtls_ssl_free(&ssl_client->ssl_ctx);
    mbedtls_ssl_config_free(&ssl_client->ssl_conf);
    mbedtls_ctr_drbg_free(&ssl_client->drbg_ctx);
    mbedtls_entropy_free(&ssl_client->entropy_ctx);
}


int data_to_read(sslclient_context *ssl_client)
{
	if (ssl_client->client == NULL) {
		return 0;
	}

    int ret, res;
    ret = mbedtls_ssl_read(&ssl_client->ssl_ctx, NULL, 0);
    //log_e("RET: %i",ret);   //for low level debug
    res = mbedtls_ssl_get_bytes_avail(&ssl_client->ssl_ctx);
    //log_e("RES: %i",res);    //for low level debug
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret < 0) {
        return handle_error(ret);
    }

    return res;
}

int send_ssl_data(sslclient_context *ssl_client, const uint8_t *data, size_t len)
{
	if (ssl_client->client == NULL) {
		return -1;
	}

    log_v("Writing HTTP request with %d bytes...", len); //for low level debug
    int ret = -1;

    while ((ret = mbedtls_ssl_write(&ssl_client->ssl_ctx, data, len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret < 0) {
            log_v("Handling error %d", ret); //for low level debug
            return handle_error(ret);
        }
        //wait for space to become available
        vTaskDelay(2);
    }

    return ret;
}

int get_ssl_receive(sslclient_context *ssl_client, uint8_t *data, int length)
{
    //log_d( "Reading HTTP response...");   //for low level debug
    int ret = -1;

    ret = mbedtls_ssl_read(&ssl_client->ssl_ctx, data, length);

    log_v( "%d bytes read", ret);   //for low level debug
    return ret;
}

static bool parseHexNibble(char pb, uint8_t* res)
{
    if (pb >= '0' && pb <= '9') {
        *res = (uint8_t) (pb - '0'); return true;
    } else if (pb >= 'a' && pb <= 'f') {
        *res = (uint8_t) (pb - 'a' + 10); return true;
    } else if (pb >= 'A' && pb <= 'F') {
        *res = (uint8_t) (pb - 'A' + 10); return true;
    }
    return false;
}

// Compare a name from certificate and domain name, return true if they match
static bool matchName(const std::string& name, const std::string& domainName)
{
    size_t wildcardPos = name.find('*');
    if (wildcardPos == std::string::npos) {
        // Not a wildcard, expect an exact match
        return name == domainName;
    }

    size_t firstDotPos = name.find('.');
    if (wildcardPos > firstDotPos) {
        // Wildcard is not part of leftmost component of domain name
        // Do not attempt to match (rfc6125 6.4.3.1)
        return false;
    }
    if (wildcardPos != 0 || firstDotPos != 1) {
        // Matching of wildcards such as baz*.example.com and b*z.example.com
        // is optional. Maybe implement this in the future?
        return false;
    }
    size_t domainNameFirstDotPos = domainName.find('.');
    if (domainNameFirstDotPos == std::string::npos) {
        return false;
    }
    return domainName.substr(domainNameFirstDotPos) == name.substr(firstDotPos);
}

// Verifies certificate provided by the peer to match specified SHA256 fingerprint
bool verify_ssl_fingerprint(sslclient_context *ssl_client, const char* fp, const char* domain_name)
{
    // Convert hex string to byte array
    uint8_t fingerprint_local[32];
    int len = strlen(fp);
    int pos = 0;
    for (size_t i = 0; i < sizeof(fingerprint_local); ++i) {
        while (pos < len && ((fp[pos] == ' ') || (fp[pos] == ':'))) {
            ++pos;
        }
        if (pos > len - 2) {
            log_d("pos:%d len:%d fingerprint too short", pos, len);
            return false;
        }
        uint8_t high, low;
        if (!parseHexNibble(fp[pos], &high) || !parseHexNibble(fp[pos+1], &low)) {
            log_d("pos:%d len:%d invalid hex sequence: %c%c", pos, len, fp[pos], fp[pos+1]);
            return false;
        }
        pos += 2;
        fingerprint_local[i] = low | (high << 4);
    }

    // Calculate certificate's SHA256 fingerprint
    uint8_t fingerprint_remote[32];
    if(!get_peer_fingerprint(ssl_client, fingerprint_remote))
        return false;

    // Check if fingerprints match
    if (memcmp(fingerprint_local, fingerprint_remote, 32))
    {
        log_d("fingerprint doesn't match");
        return false;
    }

    // Additionally check if certificate has domain name if provided
    if (domain_name)
        return verify_ssl_dn(ssl_client, domain_name);
    else
        return true;
}

bool get_peer_fingerprint(sslclient_context *ssl_client, uint8_t sha256[32])
{
    if (!ssl_client) {
        log_d("Invalid ssl_client pointer");
        return false;
    };

    const mbedtls_x509_crt* crt = mbedtls_ssl_get_peer_cert(&ssl_client->ssl_ctx);
    if (!crt) {
        log_d("Failed to get peer cert.");
        return false;
    };

    mbedtls_sha256_context sha256_ctx;
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, false);
    mbedtls_sha256_update(&sha256_ctx, crt->raw.p, crt->raw.len);
    mbedtls_sha256_finish(&sha256_ctx, sha256);

    return true;
}

// Checks if peer certificate has specified domain in CN or SANs
bool verify_ssl_dn(sslclient_context *ssl_client, const char* domain_name)
{
    log_d("domain name: '%s'", (domain_name)?domain_name:"(null)");
    std::string domain_name_str(domain_name);
    std::transform(domain_name_str.begin(), domain_name_str.end(), domain_name_str.begin(), ::tolower);

    // Get certificate provided by the peer
    const mbedtls_x509_crt* crt = mbedtls_ssl_get_peer_cert(&ssl_client->ssl_ctx);

    // Check for domain name in SANs
    const mbedtls_x509_sequence* san = &crt->subject_alt_names;
    while (san != nullptr)
    {
        std::string san_str((const char*)san->buf.p, san->buf.len);
        std::transform(san_str.begin(), san_str.end(), san_str.begin(), ::tolower);

        if (matchName(san_str, domain_name_str))
            return true;

        log_d("SAN '%s': no match", san_str.c_str());

        // Fetch next SAN
        san = san->next;
    }

    // Check for domain name in CN
    const mbedtls_asn1_named_data* common_name = &crt->subject;
    while (common_name != nullptr)
    {
        // While iterating through DN objects, check for CN object
        if (!MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &common_name->oid))
        {
            std::string common_name_str((const char*)common_name->val.p, common_name->val.len);

            if (matchName(common_name_str, domain_name_str))
                return true;

            log_d("CN '%s': not match", common_name_str.c_str());
        }

        // Fetch next DN object
        common_name = common_name->next;
    }

    return false;
}
#endif

