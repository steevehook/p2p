bin:
	go build -o .bin/server ./cmd/server
	go build -o .bin/client ./cmd/client

test:
	./scripts/test.sh --intgr

coverage:
	./scripts/test.sh --html
