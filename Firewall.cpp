#include "Firewall.H"
#include "Trie.H"
#include "Packet.H"

using namespace std;

void Firewall::addRule(string ip, int portnumber, Protocol protocol, Action action, Direction direction, string note){
    ruleTrie.insert(ip, action, protocol, direction, portnumber, note);

    Rule rule = {action, protocol, direction, note};
    allRules[ip][portnumber].push_back(rule);
}

bool Firewall::deleteRule(string ip, int port){
    // Remove the rule from the allRules ACL
    auto ipIT = allRules.find(ip);
    ruleTrie.remove(ip);

    if (ipIT != allRules.end()) {
        auto& portMap = ipIT->second;
        auto portIT = portMap.find(port);

        if (portIT != portMap.end()) {
            portMap.erase(portIT);

            if (portMap.empty()){
                allRules.erase(ipIT);
            }
            return true;
        }
    }
    return false;
}

void Firewall::clearAllRules(){
    ruleTrie.clear();
    allRules.clear();
}

Action Firewall::simulatePacket(const Packet& p){
    string ip = (p.direction == Direction::INBOUND) ? p.destIP : p.srcIP;
    int port = p.destPort;
    Direction direction = p.direction;
    Protocol protocol = p.protocol;

    // Identify the rule
    pair<string, int> parsed = ruleTrie.parseCIDR(ip);
    vector<Rule> rules = ruleTrie.getMatchingRules(parsed.first, port);

    for (const Rule& rule : rules){
        if (rule.protocol == protocol && rule.direction == direction){
            return rule.action;
        }
    }
    return Action::DENY;
}

void Firewall::displayAllRules(){
    if (allRules.empty()){
        cout << "No Rules Found!" << endl;
        return;
    }
    
    for (const auto& ipEntry : allRules){
        cout << "IP: " << ipEntry.first << endl;

        for (const auto& portEntry : ipEntry.second){
            cout << "Port: " << portEntry.first << endl;

            printRules(portEntry.second);
        }
    }
}
