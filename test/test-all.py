
from server import Handler
from client import do_init, do_read, do_change
from base64 import b64encode
import json
h = Handler()
def fake_network(url, req_obj):
    req_data = json.dumps(req_obj).encode("utf-8")
    return h.receive_request(req_data)
email = u"someone@example.com"
password_b64 = b64encode("1234")
initial_UK_b64 = do_init(email, password_b64, None, fake_network, None)
later_UK_b64 = do_read(email, password_b64, None, fake_network, None)
assert initial_UK_b64 == later_UK_b64
new_password_b64 = b64encode("abcd")
do_change(email, password_b64, new_password_b64, None, fake_network, None)
final_UK_b64 = do_read(email, new_password_b64, None, fake_network, None)
assert final_UK_b64 == initial_UK_b64
