.PHONY: start tests testAll clean

NAMESERVER = 127.0.0.2:42000
FILESERVER = file.server.one

start:
	../server_src/fsptest -p  $(NAMESERVER) -r ../nameserver/

tests:
	-cd testDir/ && ../fileget.py -n 127.0.0.2:42000 -f fsp://$(FILESERVER)/*
	diff -r testDir/ ../nameserver/$(FILESERVER)/

clean:
	rm -rf big *.txt testDir/*
