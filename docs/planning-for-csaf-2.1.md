# Plan towards CSAF 2.1

The new version of the CSAF standard is likely to come in fall this year (2026).

[Committee Specification Draft 03](https://docs.oasis-open.org/csaf/csaf/v2.1/csd03/csaf-v2.1-csd03.html)
is stable enough, so that we have started implementing it.

**This is our plan.
We appreciate your feedback in issues or email
to [@bernhardreiter](https://github.com/bernhardreiter).**

As of September 2026-10-08 the distribution part of CSAF 2.1 is close
to final, thus this is where we have started.
And early on we need a datamodel in Go to hold the CSAF file contents.

Our time frame is to have working pre-release versions
before the
[CSAF Community days in mid November](https://www.csaf.io/community-days/2026/)

## New major version 5

Adding CSAF 2.1 is a major enhancement of capabilities, so we plan
to do a major release on it. It also gives us the chance to correct
a few things and break the API while doing so.
We hope to do experimental pre-release versions soon (in mid October).

Version 5 will handle CSAF 2.1 documents and we plan to handle
2.0 ones as well.

## Keep version 3 around as old-stable major 4

As the library and tools from the repo are central to a number of CSAF
implementations, we will keep a very compatible version of major 3
around and maintain it for now.
This will be numbered [major 4](https://github.com/orgs/ISDuBA/projects/5),
to fix a defect in the data structure.  Semantic versioning and 
Go only allow us to do this with a new major number.

We will maintain the old-stable version at least as long
as the new one is not ready to fully replace it
for handling CSAF 2.0 documents.

## Improved downloading has to wait for a future major version

ISDuBA uses this library in several regards, and builds a runtime
downloader on top, that can effectively track changes over many
CSAF providers simultaneously.

Ideally this would be provided as separate library part as well, so
the `csaf_downloader` and other tools can use the better approach.

Given the time frame of about 8 weeks to support CSAF 2.1 in beta quality,
we put extracting the ISDuBA online tracking code on the back-burner.
It is likely to happen for the next major release.

## Approach

### generate Go data model from JSON schema

The new schema for CSAF 2.1 documents has grown in complexity.
We will explore generating the Go code that will hold that has data structure.
Existing JSON schema libraries should be able to do this.
If this works out, the 2.0 datamodel for the new major version 4 can
be generated like this as well.

### downloader then provider
We start with a `csaf_downloader` first and rebuild it with the new code.

We attempt to use the contravider to pose for an early CSAF 2.1 provider,
so the downloader has something to work against.
If this does not work out or not,
going for a new `csaf_provider` is the next goal.

In between a number of clutched CSAF 2.1 example files will be generated.


### ISDuBA and other tools follow
A new branch of ISDuBA will use the new _develop-5_ library version.
There we can start with trying to display the new CSAF 2.1 documents.
Initially a prototype of ISDuBA will only deal with 2.1 documents.

This is the approach we see for other tools that are based on gocsaf/csaf
as well: have development to see how the new 2.1 API is working out.

Later, support for CSAF 2.0 will be added to the new major version
as well. This is when we can think about the time frame to set an end of life
date for the old version.
