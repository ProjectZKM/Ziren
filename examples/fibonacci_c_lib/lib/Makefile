c_lib:
	mipsel-linux-gnu-g++ -mno-abicalls -msoft-float -mips2 -c add.cpp
	mipsel-linux-gnu-ar rcs libadd.a add.o
	mipsel-linux-gnu-gcc -mno-abicalls -msoft-float -mips2 -c modulus.c
	mipsel-linux-gnu-ar rcs libmodulus.a modulus.o
	rm add.o modulus.o
