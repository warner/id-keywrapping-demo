import json
from base64 import b64encode, b64decode
from twisted.application import service, internet
from twisted.web import server, resource, static

from util import SALT, KEYLEN, Oops
from scrypt import scrypt

class Handler(resource.Resource):
    def receive_request(self, tx):
        # HTTP body is utf8(json(PIECES))
        pieces = json.loads(tx.decode("utf-8"))
        if pieces[0] == "do-scrypt":
            A_b64 = pieces[1]
            salt = SALT("scrypt") # no email here, anon++
            N, r, p = [int(p) for p in pieces[2:5]]
            B = scrypt(password=b64decode(A_b64), salt=salt, N=N,r=r,p=p,
                       dkLen=KEYLEN)
            B_b64 = b64encode(B)
            resp = ["ok", B_b64]
            return json.dumps(resp).encode("utf-8")

        print "bad request", pieces
        raise Oops("bad request")

    def render_POST(self, req):
        req.content.seek(0)
        data = req.content.read()
        return self.receive_request(data)

root = static.Data("scrypt requests go to /do-scrypt", "text/plain")
root.putChild("do-scrypt", Handler())
s = internet.TCPServer(8067, server.Site(root))
application = service.Application("demo-scrypt-server")
print "Starting server.."
s.setServiceParent(application)
