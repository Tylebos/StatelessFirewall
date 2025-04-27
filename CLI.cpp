#include "Firewall.H"
#include <iostream>
#include "Packet.H"
#include <string>
#include <sstream>
#include <limits>
#include "CLI.H"

using namespace std;

bool CLI::isValidIP(const string& ip){
    stringstream ss(ip);
    string segment;
    int count = 0;
    // Break an IP into 4 octets
    while(getline(ss, segment, '.')){
        // Check if each octet has less than 3 digits
        if (segment.empty() || segment.length() > 3){
            return false;
        }
        // Confirm each value is a digit
        for (char c : segment){
            if (!isdigit(c)){return false;}
        }
        // Confirm that each segment is a valid range
        int octet = stoi(segment);
        if (octet < 0 || octet > 255){return false;}
        count++;
    }
    return count == 4;
}

// Prevents catastrophic failure in CIDR
bool CLI::isValidINT(const string& input){
    for (char c : input){
        if (!isdigit(c)){return false;}
    }
    return true;
}

void CLI::startCLI(){
    Firewall fw;
    int command;
    string userInput;

    cout << "Welcome to the Firewall application!" << endl;
    cout << "If you ever wish to exit the program please type 'exit'. *BE ADVISED IT IS CASE SENSITIVE*." << endl;

    while (true){
        cout << "Please review the following options and select an option from (0-4):  \n";
        cout << "0 - Add a Rule to the Firewall \n";
        cout << "1 - Delete a Rule from the Firewall \n";
        cout << "2 - Display Access Control List \n";
        cout << "3 - Clear Access Control List \n";
        cout << "4 - Run Packet Simulation \n";

        getline(cin, userInput);

        if(userInput == "exit"){
            cout << "Exiting Program. \n";
            break;
        }

        try {
            command = stoi(userInput);
        } catch (const invalid_argument&){
            cout << "Invalid Input!!! Please enter a valid number or type 'exit' to exit the program.\n";
            continue;
        }

        // Handle all commands
        switch (command)
        {
        // Add
        case 0: {
            cout << "Add Rule Selected\n";
            string ip;
            int CIDR;
            int port;
            string cidrInput;
            string portInput;
            string action;
            string direction;
            string protocol;
            string note;

            cout << "This Firewall works by blocking IP ranges based on CIDR Notation\n";
            cout << "So to block a /16 subnet you would type '192.168.0.0' in the IP prompt and '16' in the CIDR prompt\n";
            cout << "DO NOT INCLUDE CIDR IN YOUR IP!!! There is a separate prompt for CIDR!!!\n";
            cout << "Please enter IP address in dot decimal format for example: 192.168.1.0\n";
            cin >> ip;
            if (!isValidIP(ip)){
                cout << "Invalid IP address.\n";
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                break;
            }
            cout << "Please enter CIDR number from 8-32. Standard CIDR values are 8, 16, 24, 32. DO NOT INCLUDE '/'!!!\n";
            cin >> cidrInput;
            if (!isValidINT(cidrInput)){
                cout << "Invalid CIDR. DO NOT PUT /" << endl;
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                break;
            }
            try {
                CIDR = stoi(cidrInput);
            } catch (const invalid_argument&) {
                cout << "Invalid CIDR please enter a valid integer\n";
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                break;
            }
            if (CIDR < 8 || CIDR > 32){
                cout << "Invalid CIDR range. \n";
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                break;
            }
            if (cin.fail()){
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                cout << "Invalid input please enter a valid number DO NOT INCLUDE A '/'\n";
                break;
            }
            cout << "Please enter port number from 1 - 65,535\n";
            cin >> port;
            if (port < 1 || port > 65535){
                cout << "Invalid Port range.\n";
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                break;
            }
            if (cin.fail()){
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                cout << "Invalid input please enter a valid number\n";
                break;
            }
            cout << "Please type 'A' to allow or 'D' to deny\n";
            cin >> action;
            if (action != "A" && action != "D"){
                cout << "Invalid action. It is case sensitive.\n";
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                break;
            }
            cout << "Please Type 'I' for Inbound Traffic and 'O' for Outbound Traffic\n";
            cin >> direction;
            if (direction != "I" && direction != "O"){
                cout << "Invalid direction. It is case sensitive.\n";
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                break;
            }
            cout << "Please enter 'T' for TCP, 'U' for UDP,'I' for ICMP, or 'A' for any.\n";
            cin >> protocol;
            if (protocol != "T" && protocol != "U" && protocol != "I" && protocol != "A"){
                cout << "Invalid protocol. It is case sensitive.\n";
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                break;
            }
            cout << "Please enter a note describing what you are doing\n";
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            getline(cin, note);

            Action act = (action == "A") ? Action::ALLOW : Action::DENY;
            Direction dir = (direction == "I") ? Direction::INBOUND : Direction::OUTBOUND;
            Protocol pro;
            if (protocol == "T"){pro = Protocol::TCP;}
            else if (protocol == "U"){pro = Protocol::UDP;}
            else if (protocol == "I"){pro = Protocol::ICMP;}
            else{pro = Protocol::ANY;}
            string ipCIDR = ip + "/" + to_string(CIDR);
            fw.addRule(ipCIDR, port, pro, act, dir, note);
            cout << "Rule added successfully!\n";
            break;
        }
        // Delete
        case 1: {
            cout << "Delete Rule Selected.\n";
            string ip;
            string confirm;
            string cidrInput;
            int port;
            int CIDR;
            cout << "Enter IP to delete.\n";
            cin >> ip;
            if (!isValidIP(ip)){
                cout << "Invalid IP address.\n";
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                break;
            }
            cout << "Enter CIDR range for IP\n";
            cin >> cidrInput;
            if (!isValidINT(cidrInput)){
                cout << "Invalid CIDR. DO NOT PUT /" << endl;
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                break;
            }
            try {
                CIDR = stoi(cidrInput);
            } catch (const invalid_argument&) {
                cout << "Invalid CIDR please enter a valid integer\n";
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                break;
            }
            if (CIDR < 8 || CIDR > 32){
                cout << "Invalid CIDR range. \n";
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                break;
            }
            if (cin.fail()){
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                cout << "Invalid input please enter a valid number\n";
                break;
            }
            cout << "Enter Port Number for IP\n";
            cin >> port;
            if (port < 1 || port > 65535){
                cout << "Invalid Port range.\n";
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                break;
            }
            if (cin.fail()){
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                cout << "Invalid input please enter a valid number\n";
                break;
            }
            cout << "Are you sure you want to delete: " << ip << " ? If yes type 'Y' if no type 'N.'\n";
            cin >> confirm;
            // User input checks
            if (confirm != "N" && confirm != "Y"){
                cout << "Invalid input. Confirmation is case sensitive.\n";
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                break;
            }
            
            if (confirm == "N"){
                cout << "No rules deleted.\n";
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                break;
            }

            string ipCIDR = ip + "/" + to_string(CIDR);
            if (!fw.deleteRule(ipCIDR, port)){
                cout << "No rule found to delete\n";
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                break;
            };
            cout << "Rule Deleted!\n";
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            break;
        }
        // Display ACL
        case 2 : {
            fw.displayAllRules();
            break;
        }
        // Clear ACL
        case 3 : {
            string confirm;
            cout << "Are you sure you want to clear the ACL? If yes type 'Y' if no type 'N.'\n";
            cin >> confirm;
            if (confirm != "N" && confirm != "Y"){
                cout << "Invalid input. Confirmation is case sensitive.\n";
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                break;
            }
            
            if (confirm == "N"){
                cout << "No rules deleted.\n";
                break;
            }

            fw.clearAllRules();
            cout << "ACL has been cleared successfully.\n";
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            break;
        }
        case 4 : {
            cout << "Packet Simulation selected.\n";
            string srcIP;
            string destIP;
            int srcPort;
            int destPort;
            string protocol;
            string direction;
            cout << "The Packet simulation will show you how the firewall would react based on the rules you have created.\n";
            cout << "Here are your rules that you have created: " << endl;
            fw.displayAllRules();
            cout << "If you enter data not in the ACL you will get a Deny Action for Any\n";
            cout << "Please enter a source IP address: \n";
            cin >> srcIP;
            if (!isValidIP(srcIP)){
                cout << "Invalid Source IP address.\n";
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                break;
            }
            cout << "Please enter a destination IP address: \n";
            cin >> destIP;
            if (!isValidIP(destIP)){
                cout << "Invalid Destination IP address.\n";
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                break;
            }
            cout << "Please enter a source port: \n";
            cin >> srcPort;
            if (srcPort < 1 || srcPort > 65535){
                cout << "Invalid Source Port range.\n";
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                break;
            }
            if (cin.fail()){
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                cout << "Invalid input please enter a valid number\n";
                break;
            }
            cout << "Please enter a destination port: \n";
            cin >> destPort;
            if (destPort < 1 || destPort > 65535){
                cout << "Invalid Destination Port range.\n";
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                break;
            }
            if (cin.fail()){
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                cout << "Invalid input please enter a valid number\n";
                break;
            }
            cout << "Please Type 'I' for Inbound Traffic and 'O' for Outbound Traffic\n";
            cin >> direction;
            if (direction != "I" && direction != "O"){
                cout << "Invalid direction. It is case sensitive.\n";
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                break;
            }
            cout << "Please enter 'T' for TCP, 'U' for UDP,'I' for ICMP, or 'A' for any.\n";
            cin >> protocol;
            if (protocol != "T" && protocol != "U" && protocol != "I" && protocol != "A"){
                cout << "Invalid protocol. It is case sensitive.\n";
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                break;
            }
 
            Direction dir = (direction == "I") ? Direction::INBOUND : Direction::OUTBOUND;
            Protocol pro;
            if (protocol == "T"){pro = Protocol::TCP;}
            else if (protocol == "U"){pro = Protocol::UDP;}
            else if (protocol == "I"){pro = Protocol::ICMP;}
            else{pro = Protocol::ANY;}

            Packet p = {srcIP, destIP, pro, srcPort, destPort, dir};
            if(fw.simulatePacket(p) == Action::ALLOW){
                cout << "Traffic from: " << srcIP << " and source port: " << srcPort << " was ALLOWED over destination port: " << destPort << " to: " << destIP << endl;
            }
            else{
                cout << "Traffic from: " << srcIP << " and source port: " << srcPort << " was DENIED over destination port: " << destPort << " to: " << destIP << endl;
            }
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            break;
        }
        default: {
            cout << "Invalid input. Please select a number 0-4 or type 'exit' to exit the program.\n";
            break;
        }

        }

    }
}