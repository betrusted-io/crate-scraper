# crate-scraper

This script depends on:
- [`cargo-download`](https://github.com/Xion/cargo-download)
- A Debian/Ubuntu Linux flavored `tar` command

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
- Feb 13 2022 - `xous-core` 4abb6548cd5596a1b929c18b43b51c49857decda - v0.9.6 tag
- Mar  1 2022 - `xous-core` dd017fb291ec22e8db8949bd067df0b8dc1aaba1 - v0.9.7 tag - no change to Cargo.toml
- Mar  2 2022 - `xous-core` 06e391e5419581c3ebb0fbfcfbac49c2aabfc134 - v0.9.7 tag+2 - Subtle fix to PDDB
- Jul 19 2022 - `xous-core` 593928bd752cf3cf408e6939fde94ca19bcbefa3 - v0.9.9 tag
