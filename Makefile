
export PYTHONPATH=ska:srp-1.0:PBKDF-1.0:python-scrypt-0.1/build/lib.macosx-10.6-universal-2.6

run-server:
	twistd -noy server.py

client-init:
	python client.py EMAIL PASSWORD init
client-read:
	python client.py EMAIL PASSWORD read

repl:
	python
test:
	python test.py
