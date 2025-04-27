# StatelessFirewall
CSPB 2270 Final Project. Stateless Firewall

Project Goal: 

The goal of this project is to implement a Prefix Tree (Trie) Data Structure to maintain an Access Control List for a Stateless Firewall. 

Trie On Paper:

A Prefix Tree is a data structure best used to find the longest matching prefix for a piece of data. 
In the context of an IP, it is very useful in locating rules associated with Classless Inter Domain Routing (CIDR) ranges. 
A Trie takes in a dot-decimal IP, converts it into a bit-string, and then inserts each bit as a node up to its CIDR value. 
Once it inserts the bit-strings last bit, it marks it as the last node and assigns rules to the subnet.  

When a packet flows into or out of the firewall it calls the Longest Matching Prefix Function within the Trie class. 
The Trie is traversed and returns the rules applicable to the deepest match within the Trie. 
For example, if I had a rule for 192.168.1.0/24 to block SSH traffic and a rule for 192.168.1.224/32 to allow traffic. 
A packet for 192.168.1.15 will return DENY and a packet for 192.168.1.224 will ALLOW traffic. 

Starting The Project:

When you open the project change directories to the "code" directory:
    
    cd code

Run the following command in the terminal:

    g++ ../app/Trie.cpp ../app/Firewall.cpp ../app/CLI.cpp Main.cpp -o StatelessFirewall

Run the Demo:

The project will open a CLI which has several prompts explaining what to do. Here is my recommended path:

    Select 0 - Add rule

    Type into the IP prompt: 192.168.1.0

    Type into the CIDR prompt: 24

    Type into the port prompt: 23 

    Select DENY, TCP, INBOUND (Just follow the prompts its very user friendly).

    Once it returns you to the home screen follow the same steps except:
    
    Type in 192.168.1.224

    CIDR = 32

    ALLOW instead of DENY.
    ------------------------------------------------------------------------------
    Display your ACL so you can see it is working.
    ------------------------------------------------------------------------------
    Select 4 - Simulate packet

    Choose any normal source IP

    Option 4 will show you your ACL select an IP that matches the rule to test against that makes sense for your destination IP.
     (I generally do the ALLOW TELNET rule because it also shows that it chooses the most specific rule.)
    
    Type in an ephemeral port I recommend 45353.

    Type in port 23 for your destination port.

    Protocol and Direction should match whatever you inputted in your add rule option. (Reference your ACL if you have forgotten.)
    ------------------------------------------------------------------------------------------------------------------------------
    Run Delete Rule and follow the prompts for the Allow TELNET Rule.
    ------------------------------------------------------------------------------------------------------------------------------
    Display rules to show it worked
    ------------------------------------------------------------------------------------------------------------------------------
    Clear all rules and display to see the final option.
    ------------------------------------------------------------------------------------------------------------------------------

Summary:

This was a really comprehensive project that served as a fantastic tool for refining my C++ knowledge and helping to refresh my 
understanding of how a layer 3 Firewall would work. The Trie served as an awesome data structure for rapidly adding rules and locating the most
applicable rule to my specific subnet.

One of the greatest challenges I faced was just how much detail was involved with building a firewall. Everytime I felt like I had a feel
for what I needed for my firewall I realized I was missing a key property. For example, I initially was planning to seperate my ACL
for IP based rules and port/protocol based rules into two different data structures. But what I realized was that I needed to find a way
to associate my port and protocol based issues into the Trie. So I decided to use a unordered map inside of a TrieNode. The unordered map would
contain actions needed for a particular subnet in regards to a particular port.

Ultimately, this was a great demonstration of how you can blend several data structures together to reach an end-state that may not have
been attainable with a single structure alone. 

    


