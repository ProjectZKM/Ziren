fn main() {
    cc::Build::new()
        .file("src/c_lib/add.cpp")
        .compile("libadd.a");   // 生成 libmy_extra.a 并自动链接

    cc::Build::new()
        .file("src/c_lib/modulus.c")
        .compile("libmodulus.a");   // 生成 libmy_extra.a 并自动链接
}