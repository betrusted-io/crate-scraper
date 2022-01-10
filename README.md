# crate-scraper

This is a script that scrapes all the crates based on crates.io inside a Cargo.lock
file and stores them locally. It also can perform a quick "analysis" which simply
looks for all the `build.rs` scripts and collates them into a single file for
quicker and easier inspection of what all the `build.rs` scripts are trying to run
on your local machine.

The repo is committed with the fetched artifacts, so we have some traceability in
terms of looking at what happened in a given Xous build. Ideally this script is run
once every tagged release cycle and the files are re-committed in this repo.

It's fairly heavy-weight and a work in progress so it's not integrated into the CI
flow (yet). Perhaps once this has matured a bit and I have a better idea of exactly
what I'm looking for, this will get integrated into the CI flow. But for now,
this lets me put a pin in the source files that are involved in building `xous-core`
such that I can look at them later in case there's any problems.

Here's a log of all the times this has been run:

- Jan 10 2022 - `xous-core` eb0c1c437768bd6dbdc91fca72b328b98d3e1d7b
