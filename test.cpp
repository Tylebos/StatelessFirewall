#include <iostream>
#include <string>
#include "Trie.H"
#include "Firewall.H"
#include "Packet.H"
#include <cassert>


using namespace std;

// Trie Tests

// Printer function for vector
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

void testLongestPrefixMatch(){
    Trie trie;

    // Test and see if I can have two rules on one subset
    trie.insert("192.168.1.0/24", Action::ALLOW, Protocol::TCP, Direction::INBOUND, 443, "Allow inbound HTTPS traffic");
    trie.insert("192.168.1.0/24", Action::DENY, Protocol::UDP, Direction::INBOUND, 80, "Do not allow inbound HTTP traffic");
    // Just insert another deny rule
    trie.insert("10.0.0.0/8", Action::ALLOW, Protocol::TCP, Direction::INBOUND, 53, "Allow inbound Domain Name Service traffic");

    string testIP1 = "192.168.1.224";
    string testIP2 = "10.12.1.10";
    string testIP3 = "192.168.1.224"; 
    int testPort1 = 443;
    int testPort2 = 53;
    int testPort3 = 80;

    vector<Rule> rules1 = trie.getMatchingRules(testIP1, testPort1);
    vector<Rule> rules2 = trie.getMatchingRules(testIP2, testPort2);
    vector<Rule> rules3 = trie.getMatchingRules(testIP3, testPort3);

    cout << "Rules for: " << testIP1 << " are " << ":\n";
    printRules(rules1);

    cout << "Rules for: " << testIP2 << " are " << ":\n";
    printRules(rules2);

    cout << "Rules for: " << testIP3 << " are " << ":\n";
    printRules(rules3);
    
}

void testOverlappingCIDR(){
    Trie trie;

    trie.insert("192.168.1.0/24", Action::ALLOW, Protocol::UDP, Direction::OUTBOUND, 22, "Allow outbound traffic on SSH");
    trie.insert("192.168.0.0/16", Action::DENY, Protocol::TCP, Direction::OUTBOUND, 22, "Do not allow outbound traffic on SSH");

    string testIP = "192.168.1.224";
    int testPort = 22;
    string testIP2 = "192.168.10.224";

    vector<Rule> rules = trie.getMatchingRules(testIP, testPort);
    vector<Rule> rules2 = trie.getMatchingRules(testIP2, testPort);

    cout << "Rules for: " << testIP << " are " << ":\n";
    printRules(rules);

    cout << "Rules for: " << testIP2 << " are " << ":\n";
    printRules(rules2);
}

void testInsertandRemove(){
    Trie trie;


    trie.insert("192.168.1.0/24", Action::ALLOW, Protocol::ICMP, Direction::OUTBOUND, 22, "Allow outbound traffic on SSH");
    trie.insert("192.168.0.0/16", Action::DENY, Protocol::TCP, Direction::OUTBOUND, 22, "Do not allow outbound traffic on SSH");

    string testIP = "192.168.1.224";
    int testPort = 22;
    string testIP2 = "192.168.10.224";

    vector<Rule> rules = trie.getMatchingRules(testIP, testPort);
    vector<Rule> rules2 = trie.getMatchingRules(testIP2, testPort);

    cout << "Rules for: " << testIP << " are " << ":\n";
    printRules(rules);

    cout << "Rules for: " << testIP2 << " are " << ":\n";
    printRules(rules2);

    // Now delete them
    trie.remove("192.168.1.0/24");
    //Uncomment below if you want to see it remove all rules it will return Deny anything.
    //trie.remove("192.168.0.0/16"); 
    rules = trie.getMatchingRules(testIP, testPort);
    cout << "Rules : " << testIP << " are " << ":\n";
    printRules(rules);
}
// End Trie Tests

// Firewall Tests
void addRule_SimulateTraffic(){
    Firewall fw;
    
    //Inbound traffic test
    fw.addRule("10.0.0.0/8", 53, Protocol::UDP, Action::ALLOW, Direction::INBOUND, "All Inbound DNS Traffic");
    fw.addRule("192.168.1.0/24", 23, Protocol::TCP, Action::DENY, Direction::OUTBOUND, "Block Telnet from all internal nodes");

    Packet p = {"8.8.8.8", "10.1.1.43", Protocol::UDP, 62337, 53, Direction::INBOUND};
    Packet p2 = {"192.168.1.224", "192.168.1.223", Protocol::TCP, 61339, 23, Direction::OUTBOUND};

    assert(fw.simulatePacket(p) == Action::ALLOW);
    cout << "Inbound DNS traffic allowed test passed! \n";
    assert(fw.simulatePacket(p2) == Action::DENY);
    cout << "Outbound Telnet traffic blocked test passed! \n";
}

void addDeleteRulesTest(){
    Firewall fw;

    fw.addRule("10.0.0.0/8", 53, Protocol::UDP, Action::ALLOW, Direction::INBOUND, "All Inbound DNS Traffic");
    fw.addRule("192.168.1.0/24", 23, Protocol::TCP, Action::DENY, Direction::OUTBOUND, "Block Telnet from all internal nodes");
    fw.addRule("192.168.0.0/16", 22, Protocol::TCP, Action::ALLOW, Direction::OUTBOUND, "Block Telnet from all internal nodes");

    fw.displayAllRules();

    fw.deleteRule("192.168.1.0/24", 23);
    cout << "Rule Deleted" << endl;
    fw.displayAllRules();

    fw.clearAllRules();
    cout << "All Rules Deleted" << endl;
    fw.displayAllRules();
}

int main() {
    // Trie Tests
    cout << "\nRunning Longest Prefix Match Test:" << endl;
    testLongestPrefixMatch();
    cout << "\nRunning Overlapping Longest Prefix Match Test:" << endl;
    testOverlappingCIDR();
    cout << "\nRunning Deletion Test:" << endl;
    testInsertandRemove();
    // End Trie Tests
    // Begin Firewall Tests
    cout << "\nRunning Simulate Traffic Test:"<< endl;
    addRule_SimulateTraffic();
    cout << "\nRunning Add and Delete test:"<< endl;
    addDeleteRulesTest();
    return 0;
}
