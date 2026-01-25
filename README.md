# TrafficLens
Network Traffic Visualization and Analysis Tool

## Features 
1. Unified Web Interface
   1. Frontend and backend are implemented a single python codebase.
2. Interactive Traffic Visualizations
   1. Real time dynamic charts and diagrams
      1. Timeline Graph of packet rates
      2. Table of active flows
         1. Source/Destinations
         2. Ports
         3. Protocols
      3. Network Graph of endpoints
   2. Chat-Like Packet Narration
      1. Real-time textual feed translation
         1. Ex. ARP ("Who has 192.168.1.1? Tell 192.168.1.2")
   3. Live Capture and PCAP Import
   4. Secure User Authentication
      1. The app requires users to log in.
      2. Each user's session and data are isolated.
   5. Per-User Data Sandboxing
      1. Captured Data and uploaded files are sandboxed per user.
      2. Each user's PCAP uploads and analysis results are kept seperate and encrypted at rest.
## 