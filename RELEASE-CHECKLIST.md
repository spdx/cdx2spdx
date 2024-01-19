# Release Checklist for the CycloneDX to SPDX Utilities

- [ ] Check for any warnings from the compiler and findbugs
- [ ] Run unit tests
- [ ] Run dependency check to find any potential vulnerabilities `mvn dependency-check:check`
- [ ] Run `mvn release:prepare` - you will be prompted for the release - typically take the defaults
- [ ] Run `mvn release:perform`
- [ ] Release artifacts to Maven Central
- [ ] Create a Git release including release notes
- [ ] Zip up the files from the Maven archive and add them to the release
