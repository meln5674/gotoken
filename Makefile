.PHONY: test
test:
	ginkgo run -p --cover .
	go tool cover -html=coverprofile.out -o coverprofile.html
	go tool cover -func=coverprofile.out

.PHONY: deps
deps:
	go mod download

.PHONY: vet
vet:
	go vet


