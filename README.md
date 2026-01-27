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
### Models


### Resources
1. [Writing your first Django App Tutorial](https://docs.djangoproject.com/en/6.0/intro/tutorial01/)
   1. Testing to see if django was installed correctly
      1. ```python -m django --version```
   2. Creating a project
      1. ```django-admin startproject <project_name> <(opt="duplicate of the project name")directory_name>```
   3. Django Development Server
      1. ```python manage.py runserver```
   4. Creating and App inside Django Project
      1. ```python manage.py startapp <app_name>```
   5. Creating a View
      1. ```./<app_name>/views.py```
   6. Migrations
      1. ```python manage.py makemigrations <app_name>```
      2. ```python manage.py migrate```
   7. Creating and admin user
      1. ```python manage.py createsuperuser```
2. [Sample PCAP File](https://wiki.wireshark.org/SampleCaptures#user-content-hypertext-transport-protocol-http)