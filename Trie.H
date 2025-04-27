#ifndef Trie_H
#define Trie_H


#include <iostream>
#include <string>
#include <vector>
#include <bitset>
#include <sstream>
#include <algorithm>
#include <unordered_map>


using namespace std;

enum class Action{
    ALLOW,
    DENY
};

enum class Protocol {
    TCP,
    UDP,
    ICMP,
    ANY
};

enum class Direction {
    INBOUND,
    OUTBOUND
};

struct Rule {
    Action action;
    Protocol protocol;
    Direction direction;
    string note; // Description
};

struct TrieNode{
    TrieNode* children[2];
    bool is_end;
    unordered_map<int, vector<Rule>> portProtocolActions; // Store actions applicable to specific ports
    

    // Constructor
    TrieNode(){
        children[0] = nullptr;
        children[1] = nullptr;
        is_end = false;
        portProtocolActions = {};
    }
};





class Trie{
    private:
        TrieNode* root;

        void deleteSubtree(TrieNode* node){
            if (!node) {return;}

            deleteSubtree(node->children[0]);
            deleteSubtree(node->children[1]);

            delete node;
        }
    
    public:
        Trie();

        pair<string, int> parseCIDR(string ip);
        
        string ip_toBinary(string ip_noCIDR);
        
        void insert(string ip, Action action, Protocol protocol, Direction direction, int portNumber, string note);
        
        // Longest matching prefix logic with modifications
        vector<Rule> getMatchingRules(string ip, int portnum);

        bool remove(string ip);

        void clear();

        ~Trie();
};

#endif // Trie_H