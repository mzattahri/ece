.PHONY: test fmt lint

test:
	go test ./...
	go test -run TestGenerateInteropVectors
	$(MAKE) -C js test

fmt:
	go fmt ./...
	$(MAKE) -C js fmt

lint:
	golangci-lint run
	$(MAKE) -C js lint
