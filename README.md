# Beken-Touer  

## Introduction
Beken-Touer is an Access System for granting clients access to resources by IP address.

## Client-Server
Beken Clients communicate with the Beken Server.  The Server records the Client's IP address in a database.

### Beken
Beken Server is a TCP server that provides a HTTP API as well as static content and JavaScript to browser clients.  Beken clients use beken tokens.

### uBeken
uBeken Server is a UDP server that records the Client's IP address in a database.  uBeken clients send a custom crafted UDP packet to the server.

### Touer
Touer is a standalone tool and background process that reads the IP address database and performs necessary tasks.

