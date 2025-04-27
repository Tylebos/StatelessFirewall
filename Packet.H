#ifndef Packet_H
#define Packet_H

#include <string>
#include <iostream>
#include "Trie.H"

using namespace std;


struct Packet
{
    string srcIP;
    string destIP;
    Protocol protocol;
    int srcPort;
    int destPort;
    Direction direction;
};


#endif // Packet_H
