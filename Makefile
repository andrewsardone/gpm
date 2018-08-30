all: build-deps build

build:
	go build -o mysql-scanner .

build-deps:
	go get github.com/mcuadros/go-version

run: all
	./mysql-scanner

test-deps:
	docker pull mysql:8.0.12
	docker pull mysql:5.5.59
	docker pull mysql:5.7.23
