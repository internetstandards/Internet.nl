# Docker Integration Tests



### Debugging tests

#### Local
On test failure a video, screenshot, trace and log output regarding the failed test are placed in the `test-results/<test-name>` folder in the project source.

#### CI (Github Actions)
On test failure a video, screenshot, trace and log output regarding the failed test are generated. These can be downloaded as artifacts after the entire testrun has completed on the 'Summary' page of the Action Run: `https://github.com/internetstandards/Internet.nl/actions/runs/<run-id>`.

#### Trace view

Besides screenshot and video it is also to generate debug information in a `trace.zip` file for each failed test. The trace file contains a complete debug trace with JS console output and network graph. To generate the trace file run the integration tests with `make integration-tests-trace`. To view the trace please refer to https://playwright.dev/python/docs/trace-viewer.