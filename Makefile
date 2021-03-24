test:
	go test ./...
coverage:
	go test -failfast=true ./... -coverprofile cover.out
	go tool cover -html=cover.out
	rm cover.out
mocks:
	mockery --name=DbHandler --recursive=true --case=underscore --output=./pkg/testhelper/mocks;
	mockery --name=JWTService --recursive=true --case=underscore --output=./pkg/testhelper/mocks;
	mockery --name=KafkaProducer --recursive=true --case=underscore --output=./pkg/testhelper/mocks;
