
NAME?=go-peafowl

all:
	@ if [ ! -d "peafowl_lib" ]; then git clone https://github.com/DanieleDeSensi/Peafowl.git peafowl_lib; fi;
	@ if [ ! -f peafowl_lib/lib/libdpi.a ]; then make -C peafowl_lib; fi;
	
	go build -ldflags "-s -w"  -o $(NAME) *.go

debug:
	go build -o $(NAME) *.go

.PHONY: clean
clean:
	rm -fr $(NAME)