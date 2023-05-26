# Integration tests

An integration test suite is provided under `integration-tests/` which is used to test vital application functionality and specific edgecases against a full application stack in Docker. The application stack is setup using the Docker Compose file `docker/docker-compose.yml` and the test instance is managed by the test suite by default. To run integration tests run the following command:

    make integration-tests

To run the test suite against an existing Docker Compose instance provide the instance project name (which can be empty for default instance):

    INTERNETNL_USE_DOCKER_COMPOSE_PROJECT="" make integration-tests

