.PHONY: test fmt

test:
	go test ./...
	go test -run TestGenerateInteropVectors
	$(MAKE) -C js test

fmt:
	go fmt ./...
	$(MAKE) -C js fmt
