g++ -c -fPIC -o JNnet.o JNnet.cpp -std=c++11

g++ -shared -o libJNnet.so JNnet.o

sudo ldconfig

# 把头文件拷贝到 /usr/include/mymuduo       .so库拷贝到 /usr/lib
# if [ ! -d /usr/include/JNnet ]; then
#     mkdir /usr/include/JNnet
# fi

cp ./JNnet.h /usr/include/

cp ./libJNnet.so /usr/lib

rm JNnet.o libJNnet.so