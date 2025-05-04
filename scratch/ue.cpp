// sudo docker exec -it ueransim ./nr-ue -c config/uecfg.yaml
// sudo ./ns3 connect 10.100.200.13
// ./ns3 run scratch/ue.cpp -h 8.8.8.8 -c 10 -o captured -lpcap -lxlsxwriter

#include <iostream>
#include <getopt.h>
#include <cstring>
#include <cstdlib>
#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <fstream>
#include <vector>
#include <nlohmann/json.hpp>
#include <xlsxwriter.h>

#define PACKET_SIZE 64
#define SNAP_LEN 1518

using json = nlohmann::json;

struct PingResult {
    int seq;
    std::string status;
    long rtt_ms;
    std::string timestamp;
};

std::vector<PingResult> results;

unsigned short calculate_checksum(void *buf, int length) {
    unsigned short *data = (unsigned short *)buf;
    unsigned int sum = 0;
    while (length > 1) {
        sum += *data++;
        length -= 2;
    }
    if (length == 1)
        sum += *(unsigned char *)data;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void usage(const char *prog) {
    std::cout << "Usage: " << prog << " -h <host> [-c <count>] [-o <files_name>] [-u <ue_host>]\n";
}

std::string get_timestamp() {
    char buffer[64];
    time_t now = time(nullptr);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return buffer;
}

int main(int argc, char **argv) {
    std::string host;
    int count = 4;
    std::string out_file = "output";
    std::string hoster = "10.100.200.14";

    // Parse CLI args
    const char *optstring = "h:c:o:u:";
    const struct option longopts[] = {
        {"host", required_argument, nullptr, 'h'},
        {"count", required_argument, nullptr, 'c'},
        {"out", required_argument, nullptr, 'o'},
        {"ue", required_argument, nullptr, 'u'},
        {nullptr, 0, nullptr, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, optstring, longopts, nullptr)) != -1) {
        switch (opt) {
            case 'h': host = optarg; break;
            case 'c': count = atoi(optarg); break;
            case 'o': out_file = optarg; break;
            case 'u': hoster = optarg; break;
            default: usage(argv[0]); return 1;
        }
    }

    if (host.empty()) {
        usage(argv[0]);
        return 1;
    }

    // Resolve hostname
    struct sockaddr_in dest_addr{};
    struct hostent *host_entry = gethostbyname(host.c_str());
    if (!host_entry) {
        std::cerr << "Could not resolve host.\n";
        return 1;
    }
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr = *(struct in_addr *)host_entry->h_addr;

    // Raw socket
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    // Setup pcap capture
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("any", SNAP_LEN, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "pcap_open_live failed: " << errbuf << "\n";
        return 1;
    }

    pcap_dumper_t *pcap_file = pcap_dump_open(handle, ("trace/"+out_file+".pcap").c_str());
    if (!pcap_file) {
        std::cerr << "pcap_dump_open failed: " << pcap_geterr(handle) << "\n";
        return 1;
    }

    for (int i = 0; i < count; ++i) {
        char send_packet[PACKET_SIZE];
        memset(send_packet, 0, sizeof(send_packet));
        struct icmphdr *icmp_hdr = (struct icmphdr *)send_packet;

        icmp_hdr->type = ICMP_ECHO;
        icmp_hdr->code = 0;
        icmp_hdr->un.echo.id = getpid();
        icmp_hdr->un.echo.sequence = i + 1;
        gettimeofday((struct timeval *)(send_packet + sizeof(icmphdr)), nullptr);
        icmp_hdr->checksum = 0;
        icmp_hdr->checksum = calculate_checksum(send_packet, PACKET_SIZE);

        struct timeval start_time, end_time;
        gettimeofday(&start_time, nullptr);

        if (sendto(sockfd, send_packet, PACKET_SIZE, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) <= 0) {
            perror("sendto");
            results.push_back({i + 1, "Send Failed", -1, get_timestamp()});
            continue;
        }

        std::string command =
        "python3 -c \"from scapy.all import IP, send; import sys; "
        "send(IP(dst='" + hoster + "', proto=221)/b'" + host + "', verbose=False)\"";

        int ret = system(command.c_str());
        if (ret != 0) {
            std::cerr << "Python command failed with code " << ret << std::endl;
        }
        std::cout << "Sending..." << "\n";

        struct pcap_pkthdr *header;
        const u_char *packet;
        int res;
        bool success = false;

        for (int j = 0; j < 10; ++j) {
            res = pcap_next_ex(handle, &header, &packet);
            if (res == 1) {
                gettimeofday(&end_time, nullptr);
                long rtt = (end_time.tv_sec - start_time.tv_sec) * 1000 +
                           (end_time.tv_usec - start_time.tv_usec) / 1000;
                pcap_dump((u_char *)pcap_file, header, packet);
                results.push_back({i + 1, "Success", rtt, get_timestamp()});
                success = true;
                break;
            } else if (res == 0) {
                usleep(100000); // wait 100ms
            } else {
                std::cerr << "pcap_next_ex failed.\n";
                break;
            }
        }

        if (!success) {
            results.push_back({i + 1, "Timeout", -1, get_timestamp()});
        }

        sleep(1);
    }

    // Cleanup
    pcap_dump_close(pcap_file);
    pcap_close(handle);
    close(sockfd);

    // Write JSON
    json j;
    for (const auto &res : results) {
        j["pings"].push_back({
            {"seq", res.seq},
            {"status", res.status},
            {"rtt_ms", res.rtt_ms},
            {"timestamp", res.timestamp}
        });
    }

    int received = std::count_if(results.begin(), results.end(),
        [](const PingResult &r) { return r.status == "Success"; });

    j["summary"] = {
        {"sent", count},
        {"received", received},
        {"loss_percent", 100 - (received * 100 / count)}
    };

    std::ofstream json_out("trace/"+out_file+".json");
    json_out << j.dump(4);
    json_out.close();
    std::cout << "Saved JSON to output.json\n";

    // Write Excel
    lxw_workbook *workbook = workbook_new(("trace/"+out_file+".xlsx").c_str());
    lxw_worksheet *worksheet = workbook_add_worksheet(workbook, NULL);

    worksheet_write_string(worksheet, 0, 0, "Seq", nullptr);
    worksheet_write_string(worksheet, 0, 1, "Status", nullptr);
    worksheet_write_string(worksheet, 0, 2, "RTT (ms)", nullptr);
    worksheet_write_string(worksheet, 0, 3, "Timestamp", nullptr);

    for (size_t i = 0; i < results.size(); ++i) {
        worksheet_write_number(worksheet, i + 1, 0, results[i].seq, nullptr);
        worksheet_write_string(worksheet, i + 1, 1, results[i].status.c_str(), nullptr);
        if (results[i].rtt_ms >= 0)
            worksheet_write_number(worksheet, i + 1, 2, results[i].rtt_ms, nullptr);
        else
            worksheet_write_string(worksheet, i + 1, 2, "N/A", nullptr);
        worksheet_write_string(worksheet, i + 1, 3, results[i].timestamp.c_str(), nullptr);
    }

    workbook_close(workbook);
    std::cout << "Saved Excel to output.xlsx\n";

    std::cout << "Done. PCAP saved to " << out_file << "\n";
    return 0;
}
