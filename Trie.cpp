// Tyler Bosford
// CSPB 2270
// Trie Data Structure 


#include "Trie.H"

// Constructor
Trie::Trie() {
    root = new TrieNode();
}

Trie::~Trie(){
    deleteSubtree(root);
}

// Seperate the CIDR value to be used later in insert
pair<string, int> Trie::parseCIDR(string ip){
    size_t pos = ip.find('/');
    string ip_noCIDR = ip.substr(0,pos);
    string cidr_str = ip.substr(pos + 1);
    int cidr = stoi(cidr_str);
    pair<string, int> parsed = {ip_noCIDR, cidr};
    return parsed; 
}

// Convert to Binary Strings for Trie
string Trie::ip_toBinary(string ip_noCIDR){
    stringstream ss(ip_noCIDR);
    string bitstring = "";
    // Hold our string stream
    string octet;
    // Break apart the ip and convert to int
    while (getline(ss, octet, '.')){
        bitset<8> b(stoi(octet));
        bitstring += b.to_string();
    }
    return bitstring;
}

void Trie::insert(string ip, Action action, Protocol protocol, Direction direction, int portNumber, string note){
    pair<string, int> parsed = parseCIDR(ip);
    int cidr = parsed.second;
    string bitString = ip_toBinary(parsed.first);
    TrieNode* current = root;
    // Convert bits into nodes
    for (int i = 0; i < cidr; i++){
        char bit = bitString[i];

        // Convert to an index for TrieNode
        int index = bit - '0';
        if (current->children[index] == nullptr){
            current->children[index] = new TrieNode();
        }
        current = current->children[index];
    }
    // Mark the last node for a bit string
    current->is_end = true;
    Rule newRule = {action, protocol, direction, note};
    current->portProtocolActions[portNumber].push_back(newRule);
}

vector<Rule> Trie::getMatchingRules(string ip_noCIDR, int portnum){
    string bitString = ip_toBinary(ip_noCIDR);

    TrieNode* current = root;
    // Default response for no match is to deny
    vector<Rule> result = {Rule{Action::DENY, Protocol::ANY}};

    for (int i = 0; i < bitString.length(); i++){
        int index = bitString[i] - '0';

        if(current->children[index] == nullptr){
            break; // No explicit rules
        }
        current = current->children[index];

        if (current->is_end && current->portProtocolActions.count(portnum)){
            result = current->portProtocolActions[portnum];
        }
    }
    return result;
}

bool Trie::remove(string ip){
    TrieNode* current = root;
    pair<string, int> parsed = parseCIDR(ip);
    string bitString = ip_toBinary(parsed.first);
    int cidr = parsed.second;

    for (int i = 0; i < cidr; i++){
        char bit = bitString[i];

        int index = bit - '0';
        if (!current->children[index]){
            return false;
        }
        current = current->children[index];
    }
    if (!current->is_end){return false;}
    current->portProtocolActions.clear();
    current->is_end = false;

    return true;
}

void Trie::clear(){
    deleteSubtree(root);
    root = new TrieNode(); // reset the root to an empty node 
}





