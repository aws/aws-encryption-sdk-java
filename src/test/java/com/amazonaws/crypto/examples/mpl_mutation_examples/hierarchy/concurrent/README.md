[//]: # "Copyright Amazon.com Inc. or its affiliates. All Rights Reserved."
[//]: # "SPDX-License-Identifier: CC-BY-SA-4.0"

# AWS Cryptographic Material Providers Library Concurrency Testing Suite

Welcome to the AWS Cryptographic Material Providers Library Concurrency and Parallelization
Testing Suite 🎉!

This testing suite helps set up scenarios that we would like to run in a parallel or multithreaded environment.

Some things to keep in mind when you add tests. Think about how you will be creating resources per
thread and what kind of state you need to keep between tests.

Examples:

- [Test regular DynamoDB Client TransactWrites](ConcurrentConditionCheckWriteTest.java)
- [Test ACTIVE branch key reads while branch key creation is inflight](StorageWriteReadConcurrencyTests.java)
- [Test branch key reads while branch key versioning is inflight](StorageVersionReadConcurrencyTests.java)

[Security issue notifications](./CONTRIBUTING.md#security-issue-notifications)

## Security

If you discover a potential security issue in this project
we ask that you notify AWS/Amazon Security via our
[vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/).
Please **do not** create a public GitHub issue.
