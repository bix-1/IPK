.PHONY: start tests testAll clean

NAMESERVER = 127.0.0.2:42000
FILESERVER = file.server.one
LOGIN = xbartk07

.PHONY: start testAll testFinal pack clean

start:
	../server_src/fsptest -p  $(NAMESERVER) -r ../nameserver/

testAll:
	-cd testDir/ && ../fileget.py -n 127.0.0.2:42000 -f fsp://$(FILESERVER)/*
	diff -r testDir/ ../nameserver/$(FILESERVER)/

testFinal: clean
	cd testDir && ../fileget.py -n 147.229.176.19:3333 -f fsp://blue.server/000093.text && ../fileget.py -n 147.229.176.19:3333 -f fsp://blue.server/000020.pdf && ../fileget.py -n 147.229.176.19:3333 -f fsp://blue.server/000052.xls && ../fileget.py -n 147.229.176.19:3333 -f fsp://red.server/index && ../fileget.py -n 147.229.176.19:3333 -f fsp://green.server/*

pack:
	zip $(LOGIN)-src.zip fileget.py
	cd testDir/ && zip -r $(LOGIN)-out.zip * && mv *zip ../

clean:
	rm -rf big *.txt testDir/* *.zip
