import json
from base64 import b64encode, b64decode
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
import srp
from util import make_session_keys, encrypt_and_mac, decrypt, Oops

class Server:
    def __init__(self):
        # these three are indexed by email
        self.SRPsalt_b64 = {}
        self.SRPverifier_b64 = {}
        self.WUK_b64 = {}
        # these two are indexed by sessionid_b64
        self.verifiers = {} # -> (srp.Verifier,email) # during SRP processing
        self.sessions = {} # -> (SRPKsession, email) # after SRP
    def receive_request(self, tx):
        pieces = json.load(tx.decode("utf-8"))
        if pieces[0] == "get-salt":
            email = pieces[1]
            return self.salt_b64[email]
        if pieces[0] == "srp-1":
            sid_b64, email, A_b64 = pieces[1:4]
            if sid_b64 in self.verifier or sid_b64 in self.sessions:
                raise Oops("sessionid already claimed")
            salt = b64decode(self.SRPsalt_b64[email])
            vkey = b64decode(self.SRPverifier_b64[email])
            v = srp.Verifier(email, salt, vkey, b64decode(A_b64),
                             hash_alg=srp.SHA256)
            self.verifiers[sid_b64] = (v, email)
            s,B = v.get_challenge()
            if s is None or B is None:
                raise Oops("SRP rejected")
            resp = ["ok", b64encode(s), b64encode(B)]
            return json.dumps(resp).encode("utf-8")
        if pieces[0] == "srp-2":
            sid_b64, M_b64 = pieces[1:3]
            if sid_b64 not in self.verifiers:
                raise Oops("no such session")
            if sid_b64 in self.session:
                raise Oops("sessionid already claimed")
            (v,email) = self.verifiers.pop(sid_b64)
            HAMK = v.verify_session(b64decode(M_b64))
            if HAMK is None:
                raise Oops("SRP rejected")
            if not v.authenticated():
                raise Oops("SRP rejected")
            k_b64 = b64encode(v.get_session_key())
            self.sessions[sid_b64] = (k_b64, email)
            resp = ["ok", b64encode(HAMK)]
            return json.dumps(resp).encode("utf-8")
        if pieces[0] == "encrypted-request":
            sid_b64, enc_req_b64 = (pieces[1], pieces[2])
            if sid_b64 not in self.sessions:
                raise Oops("no such session")
            # very short-lived sessions: just one request. XXX need to time
            # out old sessions, say after 5 minutes.
            k_b64,email = self.sessions.pop(sid_b64)
            (enc1_b64,mac1_b64,enc2_b64,mac2_b64) = make_session_keys(k_b64)
            rd_b64 = decrypt(enc1_b64, mac1_b64, enc_req_b64)
            req = json.load(b64decode(rd_b64.decode("utf-8")))
            response = self.process_request(email, req)
            response_data_b64 = b64encode(json.dump(response).encode("utf-8"))
            rx_b64 = encrypt_and_mac(enc2_b64, mac2_b64, response_data_b64)
            return rx_b64
        print "bad request", pieces
        raise Oops("bad request")

    def process_request(self, email, req):
        if req[0] == "set":
            self.WUK_b64[email] = req[1]
            return ["ok"]
        if req[0] == "get":
            return ["ok", self.WUK_b64[email]]
        print "bad encrypted request", req
        raise Oops("bad request")

class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        resp = self.server.my_server.receive_request(self.rfile().read())
        self.wfile.write(resp)

listen_address = ('', 8066)
httpd = HTTPServer(listen_address, RequestHandler)
httpd.my_server = Server()

print "Starting server.."
httpd.serve_forever()
