"""Задача 10: Проверка SSL/TLS сертификата."""
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.ocsp import OCSPRequestBuilder, OCSPResponseStatus
from cryptography.hazmat.primitives import hashes, serialization


def get_certificate(hostname: str, port: int = 443) -> x509.Certificate:
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            der = ssock.getpeercert(binary_form=True)
    return x509.load_der_x509_certificate(der, default_backend())


def check_certificate(hostname: str) -> dict:
    cert = get_certificate(hostname)
    not_after = cert.not_valid_after_utc
    not_before = cert.not_valid_before_utc
    now = datetime.now(timezone.utc)
    expired = now > not_after
    not_yet_valid = now < not_before

    ocsp_status = check_ocsp_simplified(cert, hostname)

    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "expired": expired,
        "not_yet_valid": not_yet_valid,
        "days_left": (not_after - now).days if not expired else 0,
        "ocsp_status": ocsp_status,
    }


def check_ocsp_simplified(cert: x509.Certificate, hostname: str) -> str:
    """Упрощённая проверка OCSP: извлечение URL из сертификата."""
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        ocsp_urls = [
            desc.access_location.value
            for desc in aia.value
            if desc.access_method == x509.AuthorityInformationAccessOID.OCSP
        ]
        if not ocsp_urls:
            return "OCSP URL не найден в сертификате"
        return f"OCSP URL найден: {ocsp_urls[0]} (полная проверка требует запроса к responder)"
    except x509.ExtensionNotFound:
        return "Расширение AIA отсутствует — OCSP проверка недоступна"


if __name__ == "__main__":
    host = "github.com"
    info = check_certificate(host)
    print(f"Сертификат: {host}")
    print(f"  Субъект: {info['subject']}")
    print(f"  Издатель: {info['issuer']}")
    print(f"  Действителен с: {info['not_before']}")
    print(f"  Истекает: {info['not_after']}")
    print(f"  Дней до истечения: {info['days_left']}")
    print(f"  Просрочен: {info['expired']}")
    print(f"  OCSP: {info['ocsp_status']}")
