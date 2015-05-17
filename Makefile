all:
	mkdir -p build
	gcc -o build/tunet -lcrypto main.c tunet.c

clean:
	rm -rf build
