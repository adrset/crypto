##### Kompilacja getcert
g++ getcert.cpp -o program -std=c++11 -lcrypto -lssl
##### Użycie getcert
./program urls.txt
##### Kompilacja certreader
g++ certreader.cpp -o reader -lssl -lcrypto -std=c++11
##### Użycie certreader
./reader plik_z_cert
# Plik_z_cert w formacie jak tu: https://opendata.rapid7.com/sonar.ssl
