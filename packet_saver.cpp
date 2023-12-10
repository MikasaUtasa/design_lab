#include <iostream>
#include <cstdlib>

int main() {
    // Adres IP, na którym mają być przechwytywane pakiety
    std::string targetIP = "10.0.2.5";

    // Nazwa pliku, do którego mają być zapisane przechwycone pakiety
    std::string outputFile = "captured_packets.pcap";

    // Komenda do uruchomienia tcpdump
    std::string command = "sudo tcpdump -i any -w " + outputFile + " host " + targetIP;

    // Wykonaj komendę przy użyciu system()
    int result = system(command.c_str());

    if (result == 0) {
        std::cout << "Pakiety zostały przechwycone i zapisane w pliku: " << outputFile << std::endl;
    } else {
        std::cerr << "Wystąpił błąd podczas uruchamiania tcpdump." << std::endl;
    }

    return 0;
}


//http://vbsca.ca/login/login.asp
