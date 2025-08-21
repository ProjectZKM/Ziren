fn main() {
    cc::Build::new().file("src/c_lib/add.cpp").compile("libadd.a");

    cc::Build::new().file("src/c_lib/modulus.c").compile("libmodulus.a");
}
