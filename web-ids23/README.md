# WEB-IDS23

WEB-IDS23 is a network intrusion detection dataset that includes over 12 million flows, categorizing 20 attack types across FTP, HTTP/S, SMTP, SSH, and network scanning activities. This dataset is documented in the paper "Technical Report: Generating the WEB-IDS23 Dataset," which provides insights into the generation, structure, and key characteristics of the dataset.

## Data
The dataset is available as CSV files under x. Each file includes the data of one class, and each row corresponds to a flow extracted using Zeek FlowMeter. In total, the dataset includes over 12 million samples.

## Labels
The dataset contains 21 class labels, representing 20 attack types and one benign class. The attack types can be categorized into five services, FTP, HTTP/S, SMTP, SSH and Miscellaneous which includes Portscan and Hostsweep. 

| Class Label            | Description |
|------------------------|-------------|
| benign                | Normal network traffic with no attack activity. |
| bruteforce_http       | Brute-force attack on an HTTP service using Hydra. |
| bruteforce_https      | Brute-force attack on an HTTPS service using Hydra. |
| dos_http              | Denial-of-service (DoS) attack on an HTTP service using sqlmap. |
| dos_https             | Denial-of-service (DoS) attack on an HTTPS service using sqlmap. |
| ftp_login             | Brute-force attack on an FTP service using Metasploit (auxiliary/scanner/ftp/ftp_login). |
| ftp_version           | FTP service fingerprinting attack using Metasploit (auxiliary/scanner/ftp/ftp_version). |
| hostsweep_Pn          | Host discovery scan using Nmap (-Pn flag). |
| hostsweep_sn          | Host discovery scan using Nmap (-sn flag). |
| portscan              | Port scanning attack using Nmap (-sS flag). |
| revshell_http         | Reverse shell exploit over HTTP using Selenium WebDriver and netcat. |
| revshell_https        | Reverse shell exploit over HTTPS using Selenium WebDriver and netcat. |
| smtp_enum             | Enumeration of SMTP users using Metasploit (auxiliary/scanner/smtp/smtp_enum). |
| smtp_version          | SMTP service fingerprinting attack using Metasploit (auxiliary/scanner/smtp/smtp_version). |
| sql_injection_http    | SQL injection attack over HTTP using Selenium WebDriver, python-requests, and sqlmap. |
| sql_injection_https   | SQL injection attack over HTTPS using Selenium WebDriver, python-requests, and sqlmap. |
| ssh_login             | Brute-force attack on an SSH service using Metasploit (auxiliary/scanner/ssh/ssh_login). |
| ssh_login_successful  | Successful brute-force login on an SSH service using Metasploit (auxiliary/scanner/ssh/ssh_login). |
| ssrf_http             | Server-side request forgery attack over HTTP using Selenium WebDriver. |
| ssrf_https            | Server-side request forgery attack over HTTPS using Selenium WebDriver. |
| xss_http              | Cross-site scripting (XSS) attack over HTTP using Selenium WebDriver. |
| xss_https             | Cross-site scripting (XSS) attack over HTTPS using Selenium WebDriver. |

## Features
The dataset includes 82 flow-level features, which capture various aspects of network traffic. The majority of the features are extracted using the [Zeek FlowMeter tool](https://github.com/zeek-flowmeter/zeek-flowmeter). Additionally, the dataset includes information about the service type, the traffic direction and finally a fine-grained class label. 

| Feature Name                 | Source | Description |
|------------------------------|--------|-------------|
| uid                          | Zeek | The ID of the flow as given by Zeek. |
| ts                           | Zeek | Timestamp of the flow. |
| id.orig_h                    | Zeek | Originating host IP address. |
| id.resp_h                    | Zeek | Responding host IP address. |
| service                      | Zeek | The service associated with the flow, e.g., `http` or `ssl`. |
| flow_duration                | Zeek FlowMeter | The length of the flow in seconds (max precision ms). If only one packet was seen, the duration is 0. |
| fwd_pkts_tot                 | Zeek FlowMeter | The number of packets traveling in the forward direction. |
| bwd_pkts_tot                 | Zeek FlowMeter | The number of packets traveling in the backward direction. |
| fwd_data_pkts_tot            | Zeek FlowMeter | The number of packets traveling in the forward direction that have a payload. |
| bwd_data_pkts_tot            | Zeek FlowMeter | The number of packets traveling in the backward direction that have a payload. |
| fwd_pkts_per_sec             | Zeek FlowMeter | The average number of forward packets transmitted per second during the flow. If the duration is 0, this feature is also set to 0. |
| bwd_pkts_per_sec             | Zeek FlowMeter | The average number of backward packets transmitted per second during the flow. If the duration is 0, this feature is also set to 0. |
| flow_pkts_per_sec            | Zeek FlowMeter | The average number of packets transmitted per second during the flow. If the duration is 0, this feature is also set to 0. |
| down_up_ratio                | Zeek FlowMeter | The number of backward packets divided by the number of forward packets. If the number of forward packets is 0, this feature is also set to 0. |
| fwd_header_size_tot          | Zeek FlowMeter | The total number of bytes in the headers of forward packets. |
| fwd_header_size_min          | Zeek FlowMeter | The smallest header size among forward packets. |
| fwd_header_size_max          | Zeek FlowMeter | The largest header size among forward packets. |
| bwd_header_size_tot          | Zeek FlowMeter | The total number of bytes in the headers of backward packets. |
| bwd_header_size_min          | Zeek FlowMeter | The smallest header size among backward packets. |
| bwd_header_size_max          | Zeek FlowMeter | The largest header size among backward packets. |
| flow_FIN_flag_count          | Zeek FlowMeter | The total number of FIN flags seen in a TCP flow. If the flow is not TCP, this feature is set to 0. |
| flow_SYN_flag_count          | Zeek FlowMeter | The total number of SYN flags seen in a TCP flow. If the flow is not TCP, this feature is set to 0. |
| flow_RST_flag_count          | Zeek FlowMeter | The total number of RST flags seen in a TCP flow. If the flow is not TCP, this feature is set to 0. |
| fwd_PSH_flag_count          | Zeek FlowMeter | The total number of PSH flags seen in the forward direction of a TCP flow. If the flow is not TCP, this feature is set to 0. |
| bwd_PSH_flag_count          | Zeek FlowMeter | The total number of PSH flags seen in the backward direction of a TCP flow. If the flow is not TCP, this feature is set to 0. |
| flow_ACK_flag_count          | Zeek FlowMeter | The total number of ACK flags seen in a TCP flow. If the flow is not TCP, this feature is set to 0. |
| fwd_URG_flag_count          | Zeek FlowMeter | The total number of URG flags seen in the forward direction of a TCP flow. If the flow is not TCP, this feature is set to 0. |
| bwd_URG_flag_count          | Zeek FlowMeter | The total number of URG flags seen in the backward direction of a TCP flow. If the flow is not TCP, this feature is set to 0. |
| flow_CWR_flag_count         | Zeek FlowMeter | The total number of CWR flags seen in a TCP flow. If the flow is not TCP, this feature is set to 0. |
| flow_ECE_flag_count         | Zeek FlowMeter | The total number of ECE flags seen in a TCP flow. If the flow is not TCP, this feature is set to 0. |
| payload_bytes_per_second    | Zeek FlowMeter | The average number of payload bytes transmitted per second. If the duration is 0, this feature is also set to 0. |
| fwd_init_window_size        | Zeek FlowMeter | The initial window size in bytes of the first packet in the forward direction. |
| bwd_init_window_size        | Zeek FlowMeter | The initial window size in bytes of the first packet in the backward direction. |
| fwd_last_window_size        | Zeek FlowMeter | The window size in bytes of the last packet in the forward direction. |
| bwd_last_window_size        | Zeek FlowMeter | The window size in bytes of the last packet in the backward direction. |
| traffic_direction           | Set using IP addresses | Indicates the direction of traffic in the network, e.g., `client -> server`. |
| attack                      | Set using logs | Binary indicator of whether the flow is an attack. |
| attack_type                 | Set using logs | The fine-grained label. |

## Citation
If you use this dataset in your research, please cite the following paper:
```
Lanfer, E., Brockmann, D., & Aschenbruck, N. (2025). WEB-IDS23 dataset 
[Dataset]. https://doi.org/10.26249/FK2/MOCIY8
```

## License
This dataset is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).
