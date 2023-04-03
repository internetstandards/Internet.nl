from django.core.management.base import BaseCommand

from checks.http_client import http_get
from checks.tasks.cipher_info import CipherScoreAndSecLevel, cipher_infos
from checks.tasks.tls import SMTPConnection
from checks.tasks.tls_connection import (
    SSLV2,
    SSLV3,
    SSLV23,
    TLSV1,
    TLSV1_1,
    TLSV1_2,
    TLSV1_3,
    DebugConnection,
    ModernConnection,
    SSLConnectionWrapper,
)


class Command(BaseCommand):
    help = "Test connecting with the Internet.nl SSL/TLS clients."

    def add_arguments(self, parser):
        parser.add_argument(
            "server_or_url",
            help=(
                "Specifying a URL will output the page body and set the exit "
                "code to the HTTP response code. Specifing an FQDN will "
                "connect and print openssl s_client -connect like output."
            ),
        )
        parser.add_argument("--port", type=int, default=443)
        parser.add_argument("--conn", choices=["auto", "debug", "modern", "auto_starttls"], default="auto")
        parser.add_argument(
            "--tls-version",
            choices=["auto", "SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"],
            default="auto",
        )
        parser.add_argument(
            "--cipher-string",
            default="",
            help=("Cipher string to use for the connection. Default is all " "available ciphers."),
        )
        parser.add_argument("--calc-score", action="store_true", help=("Calculate the prescribed ordering score."))

    def handle(self, *args, **options):
        server_or_url = options["server_or_url"]

        if server_or_url.startswith("http"):
            response = http_get(server_or_url)
            self.stdout.write(response.text)
            exit(response.status_code)

        tls_version = {
            "auto": SSLV23,
            "SSLv2": SSLV2,
            "SSLv3": SSLV3,
            "TLSv1.0": TLSV1,
            "TLSV1.1": TLSV1_1,
            "TLSV1.2": TLSV1_2,
            "TLSv1.3": TLSV1_3,
        }.get(options["tls_version"])

        conn_class = {
            "auto": SSLConnectionWrapper,
            "debug": DebugConnection,
            "modern": ModernConnection,
            "auto_starttls": SMTPConnection,
        }.get(options["conn"])

        kwargs = {
            "server_name": server_or_url,
            "port": options["port"],
        }

        if conn_class not in (SSLConnectionWrapper, SMTPConnection):
            kwargs["version"] = tls_version

        if options["cipher_string"]:
            kwargs["ciphers"] = options["cipher_string"]

        with conn_class(**kwargs) as conn:
            # Output a partial version of the openssl s_client -connect output:
            self.stdout.write(f"CONNECTED({conn.__class__.__name__})")

            if isinstance(conn, ModernConnection):
                self.stdout.write("---")
                self.stdout.write(f"Peer signing digest: {conn.get_peer_signature_digest()}")
                self.stdout.write(f"Peer signature type: {conn.get_peer_signature_type()}")
                self.stdout.write("---")

            self.stdout.write(f"New, {conn.get_ssl_version().name}, Cipher is " f"{conn.get_current_cipher_name()}")

            if isinstance(conn, DebugConnection):
                self.stdout.write(f"Compression: {conn.get_current_compression_method()}")
                self.stdout.write(f"Secure Renegotiation: {conn.get_secure_renegotiation_support()}")

            self.stdout.write(conn.get_session().as_text())

            # Output the score if requested.
            if options["calc_score"]:
                ci = cipher_infos.get(conn.get_current_cipher_name())
                self.stdout.write(f"Score Header   : " f"{CipherScoreAndSecLevel.get_score_header()}")
                self.stdout.write(
                    f"Score Bit Flags: "
                    f"{CipherScoreAndSecLevel.format_score(CipherScoreAndSecLevel.calc_cipher_score(ci))}"
                )
