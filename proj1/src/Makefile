start:
	../server_src/fsptest -p  127.0.0.2:42000 -r ../nameserver/

test1:
	./fileget.py -n 127.0.0.2:42000 -f fsp://file.server.one/a1.txt

testAll:
	./fileget.py -n 127.0.0.2:42000 -f fsp://file.server.one/*

clean:
	
