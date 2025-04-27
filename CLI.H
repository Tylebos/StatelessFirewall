#ifndef CLI_H
#define CLI_H

#include "Firewall.H"
#include <iostream>
#include "Packet.H"
#include <string>
#include <sstream>
#include <limits>



using namespace std;

class CLI {
    public:
        bool isValidIP(const string& ip);
        bool isValidINT(const string& input);
        void startCLI();
};


#endif //CLI_H