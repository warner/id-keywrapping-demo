import json
from base64 import b64encode, b64decode
from twisted.application import service, internet
from twisted.web import server, resource, static

import srp
from util import make_session_keys, encrypt_and_mac, decrypt, Oops

class Handler(resource.Resource):
    def __init__(self):
        resource.Resource.__init__(self)
        # these three are indexed by email (unicode)
        self.SRPverifier_b64 = {}
        self.WUK_b64 = {}
        # these two are indexed by sessionid_b64
        self.verifiers = {} # -> (srp.Verifier, email) # during SRP
        self.sessions = {} # -> (SRPKsession, email) # after SRP

    def receive_request(self, tx):
        # HTTP body is utf8(json(PIECES))
        pieces = json.loads(tx.decode("utf-8"))
        if pieces[0] == "magic-init":
            # PIECES = ["magic-init", email, b64(SRPv)]
            # reponse: "ok"
            print "MAGIC"
            email, SRPverifier_b64 = pieces[1:3]
            self.SRPverifier_b64[email] = SRPverifier_b64
            return "ok"
        if pieces[0] == "srp-1":
            # PIECES = ["srp-1", b64(sessionid), email, b64(A)]
            # response: utf8(json(["ok", b64(s), b64(B)]))
            sid_b64, email, A_b64 = pieces[1:4]
            if sid_b64 in self.verifiers or sid_b64 in self.sessions:
                raise Oops("sessionid already claimed")
            salt = ""
            vkey = b64decode(self.SRPverifier_b64[email])
            v = srp.Verifier(email.encode("utf-8"), salt,
                             vkey, b64decode(A_b64),
                             hash_alg=srp.SHA256)
            self.verifiers[sid_b64] = (v, email)
            s,B = v.get_challenge()
            if s is None or B is None:
                raise Oops("SRP rejected (A)")
            resp = ["ok", b64encode(s), b64encode(B)]
            return json.dumps(resp).encode("utf-8")
        if pieces[0] == "srp-2":
            # PIECES = ["srp-2", b64(sessionid), b64(M)]
            # response: utf8(json(["ok", b64(HAMK)]))
            sid_b64, M_b64 = pieces[1:3]
            if sid_b64 not in self.verifiers:
                raise Oops("no such session")
            if sid_b64 in self.sessions:
                raise Oops("sessionid already claimed")
            (v,email) = self.verifiers.pop(sid_b64)
            HAMK = v.verify_session(b64decode(M_b64))
            if HAMK is None:
                raise Oops("SRP rejected (M)")
            if not v.authenticated():
                raise Oops("SRP rejected")
            k_b64 = b64encode(v.get_session_key())
            self.sessions[sid_b64] = (k_b64, email)
            resp = ["ok", b64encode(HAMK)]
            return json.dumps(resp).encode("utf-8")
        if pieces[0] == "encrypted-request":
            # PIECES = ["encrypted-request", b64(sessionid), b64(encreqdata)]
            # reqdata = utf8(json([REQ]))
            # response = b64(enc(utf8(json(RESP)))
            sid_b64, enc_req_b64 = (pieces[1], pieces[2])
            if sid_b64 not in self.sessions:
                raise Oops("no such session")
            # We use very short-lived sessions for now: just one request.
            # TODO: need to time out old sessions, say after 5 minutes.
            k_b64,email = self.sessions.pop(sid_b64)
            (enc1_b64,mac1_b64,enc2_b64,mac2_b64) = make_session_keys(k_b64)
            rd_b64 = decrypt(enc1_b64, mac1_b64, enc_req_b64)
            req = json.loads(b64decode(rd_b64).decode("utf-8"))
            response = self.process_request(email, req)
            response_data_b64 = b64encode(json.dumps(response).encode("utf-8"))
            rx_b64 = encrypt_and_mac(enc2_b64, mac2_b64, response_data_b64)
            return rx_b64
        print "bad request", pieces
        raise Oops("bad request")

    def process_request(self, email, req):
        if req[0] == "set":
            # REQ = ["set", b64(WUK)]
            # RESP = ["ok"]
            print " SET"
            self.WUK_b64[email] = req[1]
            return ["ok"]
        if req[0] == "get":
            # REQ = ["get"]
            # RESP = ["ok", b64(WUK)]
            print " GET"
            return ["ok", self.WUK_b64[email]]
        if req[0] == "change":
            # REQ = ["change", newSRPv, newWUK]
            # RESP = ["ok"]
            new_SRPverifier_b64, new_WUK_b64 = req[1:]
            print " CHANGE: %s" % (email,)
            self.SRPverifier_b64[email] = new_SRPverifier_b64
            self.WUK_b64[email] = new_WUK_b64
            return ["ok"]
        if req[0] == "delete":
            # REQ = ["delete"]
            # RESP = ["ok"]
            del self.WUK_b64[email]
            del self.SRPverifier_b64[email]
            return ["ok"]
        print "bad encrypted request", req
        raise Oops("bad request")

    def render_POST(self, req):
        req.content.seek(0)
        data = req.content.read()
        return self.receive_request(data)

root = static.Data("hi", "text/plain")
root.putChild("go", Handler())
s = internet.TCPServer(8066, server.Site(root))
application = service.Application("demo-server")
print "Starting server.."
s.setServiceParent(application)
