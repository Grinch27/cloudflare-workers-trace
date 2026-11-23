# 待确认：公网单栈端点、真实 DNS 权威数据源与日志交付延迟。
# 歧义：回环客户端提供本地自测的传输证据，公网浏览器的 DNS 路径还需实测。
# 后续研究：从可验证的公网客户端运行相同的 A/AAAA 和 TLS 矩阵。
# 潜在优化：在启用可信权威数据源后记录更长时间的延迟分布。
# 风险：测试证书、权威查询和存储限于回环及当前进程，不要使用生产标识或私钥。
# 验证重点：A-only、AAAA-only、双栈 TLS、随机标识关联与真实 DNSSEC 验证器对照。

"""Run the isolated DNS and HTTPS lab against the Pages handlers."""

from contextlib import contextmanager
import ctypes
import ctypes.util
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import secrets
import select
import socketserver
import subprocess
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlsplit

from cryptography.hazmat.primitives.asymmetric import ec
import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset


ROOT = Path(__file__).resolve().parent
V4 = "127.0.0.1"
V6 = "::1"
MATRIX = {
    "a.probe.test": ("ipv4", {"A": V4}),
    "aaaa.probe.test": ("ipv6", {"AAAA": V6}),
    "dual.probe.test": ("dual", {"A": V4, "AAAA": V6}),
}
NONCE = re.compile(r"^[a-f0-9]{32}\.dns\.probe\.test$")
# Use a reserved example domain via the isolated authority. Unbound handles .test locally.
SIGNED_ZONE = dns.name.from_text("signed.probe.example.net.")
GOOD_NAME = dns.name.from_text("good", origin=SIGNED_ZONE)
BAD_NAME = dns.name.from_text("bad", origin=SIGNED_ZONE)


class Authority:
    """Serve controlled answers and capture the UDP source of nonce queries."""

    def __init__(self):
        self._lock = threading.Lock()
        self._observations = {}
        self._key = ec.generate_private_key(ec.SECP256R1())
        self.dnskey = dns.dnssec.make_dnskey(self._key.public_key(), "ECDSAP256SHA256", flags=257)

    def observations(self, name):
        with self._lock:
            return list(self._observations.get(name, ()))

    def _signed(self, records, bogus=False):
        signature = dns.dnssec.sign(records, self._key, SIGNED_ZONE, self.dnskey, lifetime=600)
        if bogus:
            raw = signature.signature
            signature = signature.replace(signature=bytes([raw[0] ^ 1]) + raw[1:])
        return [records, dns.rrset.from_rdata(records.name, records.ttl, signature)]

    def respond(self, request, source_ip):
        question = request.question[0]
        name = question.name.to_text(omit_final_dot=True).lower()
        query_type = dns.rdatatype.to_text(question.rdtype)
        response = dns.message.make_response(request)
        response.flags |= dns.flags.AA
        if question.name == SIGNED_ZONE and query_type == "DNSKEY":
            keyset = dns.rrset.from_rdata(SIGNED_ZONE, 60, self.dnskey)
            response.answer.extend(self._signed(keyset))
        elif question.name in (GOOD_NAME, BAD_NAME) and query_type == "A":
            records = dns.rrset.from_text(question.name, 60, "IN", "A", V4)
            response.answer.extend(self._signed(records, bogus=question.name == BAD_NAME))
        elif NONCE.fullmatch(name):
            with self._lock:
                self._observations.setdefault(name, []).append({
                    "name": name, "queryType": query_type, "sourceIp": source_ip,
                    "observedAt": time.time_ns() // 1_000_000,
                })
            if query_type == "A":
                response.answer.append(dns.rrset.from_text(question.name, 15, "IN", "A", V4))
        elif name in MATRIX:
            address = MATRIX[name][1].get(query_type)
            if address:
                response.answer.append(dns.rrset.from_text(question.name, 15, "IN", query_type, address))
        else:
            response.set_rcode(dns.rcode.NXDOMAIN)
        return response


class DnsRequest(socketserver.BaseRequestHandler):
    def handle(self):
        packet, connection = self.request
        request = dns.message.from_wire(packet)
        if len(request.question) == 1:
            response = self.server.authority.respond(request, self.client_address[0])
            connection.sendto(response.to_wire(), self.client_address)


class EvidenceRequest(BaseHTTPRequestHandler):
    def do_GET(self):
        target = urlsplit(self.path)
        name = parse_qs(target.query).get("name", [""])[0]
        if target.path != "/observations" or not NONCE.fullmatch(name):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        body = json.dumps({"observations": self.server.authority.observations(name)}).encode()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


@contextmanager
def background(server, authority):
    with server:
        server.authority = authority
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            thread.join()


@contextmanager
def https_probe(directory, evidence_port):
    certificate = directory / "lab.crt"
    key = directory / "lab.key"
    names = [*MATRIX, "page.probe.test", "*.dns.probe.test"]
    san = "subjectAltName=" + ",".join("DNS:" + name for name in names)
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
         "-nodes", "-days", "1", "-subj", "/CN=page.probe.test", "-addext", san,
         "-keyout", str(key), "-out", str(certificate)],
        check=True, timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    with subprocess.Popen(
        ["node", str(ROOT / "probe-lab-runtime.mjs"), str(key), str(certificate), str(evidence_port)],
        stdout=subprocess.PIPE, text=True, stdin=subprocess.DEVNULL,
    ) as process:
        try:
            if not select.select([process.stdout], [], [], 10)[0]:
                raise TimeoutError("Local HTTPS probe did not start")
            ports = json.loads(process.stdout.readline())
            yield certificate, ports
        finally:
            process.terminate()
            process.wait(timeout=5)


def query(port, name, kind, want_dnssec=False):
    message = dns.message.make_query(name, kind, want_dnssec=want_dnssec)
    return dns.query.udp(message, V4, port=port, timeout=2)


def https(certificate, hostname, port, address, path):
    family = 6 if ":" in address else 4
    curl_address = "[" + address + "]" if family == 6 else address
    return subprocess.run(
        ["curl", "-q", "--noproxy", "*", f"-{family}", "--silent", "--show-error",
         "--connect-timeout", "2", "--max-time", "3", "--cacert", str(certificate),
         "--resolve", f"{hostname}:{port}:{curl_address}", "--write-out", "\n%{http_code} %{remote_ip}",
         f"https://{hostname}:{port}{path}"],
        check=False, capture_output=True, text=True, timeout=5,
    )


def assert_https(response, address):
    assert response.returncode == 0, response.stderr
    body, metrics = response.stdout.rsplit("\n", 1)
    status, remote_ip = metrics.split()
    assert status == "200"
    assert remote_ip == address
    return json.loads(body)


def verify_address_matrix(dns_port, certificate, ports):
    checks = 0
    for hostname, (role, published) in MATRIX.items():
        results = []
        for kind, address, family in (("A", V4, 4), ("AAAA", V6, 6)):
            answer = query(dns_port, hostname, kind)
            returned = [item.address for rrset in answer.answer for item in rrset]
            assert answer.rcode() == dns.rcode.NOERROR and answer.flags & dns.flags.AA
            assert returned == ([published[kind]] if kind in published else [])
            attempt = https(certificate, hostname, ports[role], address, "/_probe/address")
            if kind in published:
                probe = assert_https(attempt, address)
                assert probe["type"] == "address-family"
                assert probe["hostname"] == hostname
                assert (probe["ipVersion"], probe["visibleIp"]) == (family, address)
                results.append(f"{kind} + IPv{family} HTTPS 200")
            else:
                assert attempt.returncode == 7, attempt.stdout + attempt.stderr
                results.append(f"no {kind} + IPv{family} TCP refused")
            checks += 1
        print(f"{role}: {', '.join(results)}", flush=True)
    return checks


def verify_nonce(dns_port, certificate, port):
    nonce = secrets.token_hex(16)
    hostname = nonce + ".dns.probe.test"
    path = "/_probe/dns-evidence?nonce=" + nonce
    before = assert_https(https(certificate, "page.probe.test", port, V4, path), V4)
    assert before["status"] == "not-observed"
    started = time.monotonic()
    reply = query(dns_port, hostname, "A")
    assert reply.answer[0][0].address == V4
    reachability = assert_https(https(certificate, hostname, port, V4, "/_probe/dns"), V4)
    assert reachability["type"] == "dns-http-reachability" and reachability["hostname"] == hostname
    evidence = assert_https(https(certificate, "page.probe.test", port, V4, path), V4)
    assert evidence["status"] == "observed" and len(evidence["observations"]) == 1
    item = evidence["observations"][0]
    assert (item["sourceIp"], item["queryType"]) == (V4, "A")
    elapsed = (time.monotonic() - started) * 1000
    other = "/_probe/dns-evidence?nonce=" + secrets.token_hex(16)
    assert assert_https(https(certificate, "page.probe.test", port, V4, other), V4)["status"] == "not-observed"
    print(f"nonce: real UDP query, matching HTTPS evidence on first lookup in {elapsed:.1f} ms; unrelated nonce empty", flush=True)


class UnboundResult(ctypes.Structure):
    # libunbound(3) defines this prefix of struct ub_result.
    _fields_ = [
        ("qname", ctypes.c_char_p), ("qtype", ctypes.c_int), ("qclass", ctypes.c_int),
        ("data", ctypes.c_void_p), ("lengths", ctypes.c_void_p), ("canonname", ctypes.c_char_p),
        ("rcode", ctypes.c_int), ("answer_packet", ctypes.c_void_p), ("answer_len", ctypes.c_int),
        ("havedata", ctypes.c_int), ("nxdomain", ctypes.c_int),
        ("secure", ctypes.c_int), ("bogus", ctypes.c_int), ("why_bogus", ctypes.c_char_p),
    ]


def verify_dnssec(dns_port, authority):
    library = ctypes.util.find_library("unbound")
    if not library:
        raise RuntimeError("libunbound is required for the DNSSEC validation controls")
    unbound = ctypes.CDLL(library)
    pointer, text, integer = ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int
    result_pointer = ctypes.POINTER(UnboundResult)
    unbound.ub_ctx_create.restype = pointer
    unbound.ub_ctx_delete.argtypes = [pointer]
    unbound.ub_ctx_delete.restype = None
    unbound.ub_ctx_set_option.argtypes = [pointer, text, text]
    unbound.ub_ctx_set_stub.argtypes = [pointer, text, text, integer]
    unbound.ub_ctx_set_fwd.argtypes = [pointer, text]
    unbound.ub_ctx_add_ta.argtypes = [pointer, text]
    unbound.ub_resolve.argtypes = [pointer, text, integer, integer, ctypes.POINTER(result_pointer)]
    unbound.ub_resolve_free.argtypes = [result_pointer]
    unbound.ub_resolve_free.restype = None
    unbound.ub_strerror.argtypes = [integer]
    unbound.ub_strerror.restype = text

    def check(code):
        if code:
            raise RuntimeError(unbound.ub_strerror(code).decode())

    # Confirm the authority sends an answer and an RRSIG for both test names.
    for name in (GOOD_NAME, BAD_NAME):
        response = query(dns_port, name, "A", want_dnssec=True)
        assert response.rcode() == dns.rcode.NOERROR
        assert [rrset.rdtype for rrset in response.answer] == [dns.rdatatype.A, dns.rdatatype.RRSIG]

    ctx = unbound.ub_ctx_create()
    if not ctx:
        raise RuntimeError("Unbound context initialization failed")
    try:
        local = f"{V4}@{dns_port}".encode()
        check(unbound.ub_ctx_set_option(ctx, b"do-not-query-localhost:", b"no"))
        check(unbound.ub_ctx_set_option(ctx, b"qname-minimisation:", b"no"))
        check(unbound.ub_ctx_set_fwd(ctx, local))
        check(unbound.ub_ctx_set_stub(ctx, SIGNED_ZONE.to_text().encode(), local, 0))
        anchor = f"{SIGNED_ZONE} 60 IN DNSKEY {authority.dnskey}".encode()
        check(unbound.ub_ctx_add_ta(ctx, anchor))

        for name, expected in ((GOOD_NAME, (True, False)), (BAD_NAME, (False, True))):
            result = result_pointer()
            check(unbound.ub_resolve(ctx, name.to_text().encode(), dns.rdatatype.A, dns.rdataclass.IN, ctypes.byref(result)))
            try:
                row = result.contents
                # libunbound returns the resolver's validation flags alongside the raw answer.
                observed = (bool(row.secure), bool(row.bogus))
                assert observed == expected, (name.to_text(), observed, row.why_bogus)
                if name == GOOD_NAME:
                    assert row.rcode == dns.rcode.NOERROR and row.havedata
                print(f"DNSSEC {name.labels[0].decode()}: RCODE={dns.rcode.to_text(row.rcode)}, secure={bool(row.secure)}, bogus={bool(row.bogus)}", flush=True)
            finally:
                unbound.ub_resolve_free(result)
    finally:
        unbound.ub_ctx_delete(ctx)


def main():
    authority = Authority()
    with tempfile.TemporaryDirectory(prefix="trace-probe-lab-") as directory:
        with background(socketserver.ThreadingUDPServer((V4, 0), DnsRequest), authority) as dns_port:
            with background(ThreadingHTTPServer((V4, 0), EvidenceRequest), authority) as evidence_port:
                with https_probe(Path(directory), evidence_port) as (certificate, ports):
                    checks = verify_address_matrix(dns_port, certificate, ports)
                    verify_nonce(dns_port, certificate, ports["dual"])
                    verify_dnssec(dns_port, authority)
    print(f"PASS {checks} address-family checks, nonce association and 2 DNSSEC controls")


if __name__ == "__main__":
    main()
