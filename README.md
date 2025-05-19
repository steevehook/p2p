# P2P Client / Server

This is a simple P2P client/server that allows peer to peer communication over `TCP` sockets,
with E2E encryption using `ECDH` (Elliptic Curve Diffie-Hellman) and `AES` (Advanced Encryption Standard)
for symmetric encryption and decryption of messages.

## Features

- Connect to multiple peers
- Send and receive money between peers
- Communication is E2E encrypted

## Run

### Server

```shell
# run with the default port (9000)
go run cmd/server/main.go

# or if you want to specify the port
go run cmd/server/main.go --port 8000
```

### Client

```shell
# connect to the default server address (localhost:9000)
go run cmd/client/main.go

# or if you want to specify a server address
go run cmd/client/main.go --address localhost:9000
```

```shell
# to see the available commands
help

# to display the available balance
balance

# copy the peer id displayed at the top to connect to a peer
connect <peer_id>

# to send money to a peer
pay <amount>

# disconnect from the server
exit
```

## Test

```shell
make test
```

## Build

```shell
make bin
```
