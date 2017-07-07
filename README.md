# wpwn
pwn your (or your friend's) wordpress

![](https://img.shields.io/badge/wpwn%20version-0.0.1-brightgreen.svg)
![](https://img.shields.io/badge/kotlin%20version-1.1.3-brightgreen.svg)
![](https://img.shields.io/badge/gradle%20version-4.0-brightgreen.svg)

## Getting Started

wpwn is not even in alpha stage yet. Only detection of certain routes with certain characteristics is implemented so far. To try it out:

```sh
# install sdkman
curl -s "https://get.sdkman.io" | bash

# install kotlin and gradle
sdkman i kotlin 1.1.3-2
sdkman i gradle 4.0

# build and run
./build.sh
./wpwn <url>
```
