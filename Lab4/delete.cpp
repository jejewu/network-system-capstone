#include <stdlib.h> //system
#include <iostream>
#include <string>

using namespace std;

int main(){
    int number;
    cin >> number;
    system("ip link delete br0");
    string s = "ip link delete GRETAP";
    for(int i = 0; i <= number; i++){
        string temp = s + to_string(i);
        system(temp.c_str());
    }
}