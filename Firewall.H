#ifndef Firewall_H
#define Firewall_H

#include "Trie.H"
#include "Packet.H"
#include <iostream>
#include <algorithm>
#include <vector>
#include <string>
#include <unordered_map>

using namespace std;


class Firewall {
    private:
        Trie ruleTrie;
        unordered_map<string, unordered_map<int, vector<Rule>>> allRules;

        string protocolToString(Protocol protocol) {
            switch (protocol) {
                case Protocol::TCP: return "TCP";
                case Protocol::UDP: return "UDP";
                case Protocol::ICMP: return "ICMP";
                default: return "UNKNOWN";
            }
        }
    
        void printRules(const vector<Rule>& rules){
            for (const Rule rule : rules){
                cout << "Action: " << (rule.action == Action::ALLOW ? "ALLOW" : "DENY")
                << ", Protocol: " << protocolToString(rule.protocol)
                << ", Direction: " << (rule.direction == Direction::INBOUND ? "INBOUND" : "OUTBOUND")
                << ", Note: " << rule.note << endl;
            }
}
    
    public:
        void addRule(string ip, int port, Protocol protocol, Action action, Direction direction, string note);

        bool deleteRule(string ip, int port);

        void clearAllRules();

        Action simulatePacket(const Packet& p);

        void displayAllRules();
};


#endif // Firewall_H