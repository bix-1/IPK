.PHONY: start tests testAll clean

start:
	../server_src/fsptest -p  127.0.0.2:42000 -r ../nameserver/

tests:
	./fileget.py -n 127.0.0.2:42000 -f fsp://file.server.one/big && diff big ../nameserver/file.server.one/big

testAll:
	./fileget.py -n 127.0.0.2:42000 -f fsp://file.server.one/*

clean:
	rm -rf big *.txt
