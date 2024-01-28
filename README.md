# Design Laboratory
Autorzy: Mateusz Furgała, Maciej Dawczak

Program packet_saver to działający już program sprawdza tablicę arp i znajduje adresy ip urządzeń do niego podłaćzonych. Rozpoczyna zapisywaanie pakietów dala każdego nowo podłączonego urządzenia. 
W razie potrzeby należy zmienić nazwę interfejsu na którym jest nasz access point.

Kompilacja:

sudo g++ packet_saver.cpp -o packet_saver -lpcap
sudo ./packet_saver
