
export PYTHONPATH=.:ska:srp-1.0:python-scrypt-0.1/build/lib.macosx-10.6-universal-2.6

start:
	twistd --pidfile logs/server.pid --logfile logs/server.log -y server.py
	twistd --pidfile logs/scrypt-server.pid --logfile logs/scrypt-server.log -y scrypt-server.py

stop:
	-kill `cat logs/server.pid`
	-kill `cat logs/scrypt-server.pid`

client-init:
	python client.py EMAIL PASSWORD init
client-read:
	python client.py EMAIL PASSWORD read

repl:
	python

test-all:
	python test/test-all.py
test-pbkdf:
	PYTHONPATH=.:PBKDF-1.0 python test/compare_pbkdf.py

.PHONY: js-build js
js-build:
	cd js && npm install
js:
	cd js && npm start
# then open http://localhost:8080/
