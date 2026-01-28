# TrafficLens
Network Traffic Visualization and Analysis Tool

## Features 
1. Unified Web Interface
   1. Frontend and backend are implemented a single codebase.
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

## Structure

### Javascript Runtime
1. [Bun](https://bun.com/docs)
   1. ```bun run dev```

### Framework
1. [NextJS](https://nextjs.org/docs/app)

### ORM
1. [Prisma](https://www.prisma.io/docs/guides/nextjs)
   1. ```bunx prisma migrate dev --name init```
   2. ```bunx prisma generate```

### Database
1. [Sqlite](https://www.prisma.io/docs/orm/overview/databases/sqlite) 

### Authentication
1. My own with heavy inspiration from -> [Better-Auth](https://www.better-auth.com/docs)

### UI Library
1. [Shadcn](https://ui.shadcn.com/)
2. [TailwindCSS]()
   1. ```bun install tailwindcss @tailwindcss/postcss postcss```


### Resources

1. [Sample PCAP File](https://wiki.wireshark.org/SampleCaptures#user-content-hypertext-transport-protocol-http) 