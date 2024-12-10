# BETTERCHECK

Better than nothing.

## What is it?

A CLI tool that helps evaluate Python packages for security concerns before installing them. Performs checks against multiple vulnerability databases and provides useful metrics about package health.

### bettercheck Analysis of bettercheck
```sh
(.venv) % bettercheck-yourself

Analyzing requests...

Analyzing click...

Analyzing packaging...

Analyzing pygithub...

Analyzing pypistats...

Analyzing jsonschema...

Analyzing aiohttp...

Analyzing dataclasses...

Report saved to: ./reports/bettercheck-20241210_170638.json

=== Dependencies Security Analysis ===

Total packages analyzed: 8
Total vulnerabilities found: 33


requests:
-------------------
Version: 2.32.3
Monthly downloads: 580,975,452
Vulnerabilities: 11
- [OSV] GHSA-652x-xj99-gmcc
- [OSV] GHSA-9wx4-h78v-vm56
- [OSV] GHSA-cfj3-7x9c-4p3h
- [OSV] GHSA-j8r2-6x86-q33q
- [OSV] GHSA-pg2w-x9wp-vw92
- [OSV] GHSA-x84v-xcm2-53pg
- [OSV] PYSEC-2014-13
- [OSV] PYSEC-2014-14
- [OSV] PYSEC-2015-17
- [OSV] PYSEC-2018-28
- [OSV] PYSEC-2023-74

GitHub Metrics:
Stars: 52,266
Forks: 9,339
Open Issues: 254
Last Update: 2024-11-10 16:18:37+00:00

click:
-------------------
Version: 8.1.7
Monthly downloads: 259,210,862
No known vulnerabilities

GitHub Metrics:
Stars: 15,848
Forks: 1,405
Open Issues: 104
Last Update: 2024-12-07 20:10:36+00:00

packaging:
-------------------
Version: 24.2
Monthly downloads: 513,411,357
No known vulnerabilities

GitHub Metrics:
Stars: 628
Forks: 251
Open Issues: 104
Last Update: 2024-12-01 15:33:46+00:00

pygithub:
-------------------
Version: 2.5.0
Monthly downloads: 35,947,481
No known vulnerabilities

GitHub Metrics:
Stars: 7,072
Forks: 1,792
Open Issues: 354
Last Update: 2024-12-04 08:56:01+00:00

pypistats:
-------------------
Version: 1.7.0
Monthly downloads: 26,193
No known vulnerabilities

GitHub Metrics:
Stars: 200
Forks: 28
Open Issues: 9
Last Update: 2024-12-08 11:29:21+00:00

jsonschema:
-------------------
Version: 4.23.0
Monthly downloads: 183,583,243
No known vulnerabilities

GitHub Metrics:
Stars: 4,643
Forks: 582
Open Issues: 38
Last Update: 2024-12-09 19:57:02+00:00

aiohttp:
-------------------
Version: 3.11.10
Monthly downloads: 209,496,974
Vulnerabilities: 22
- [OSV] GHSA-27mf-ghqm-j3j8
- [OSV] GHSA-45c4-8wx5-qw6w
- [OSV] GHSA-5h86-8mv2-jq9f
- [OSV] GHSA-5m98-qgg9-wh84
- [OSV] GHSA-7gpw-8wmc-pm8g
- [OSV] GHSA-8495-4g3g-x7pr
- [OSV] GHSA-8qpw-xqxj-h4r2
- [OSV] GHSA-gfw2-4jvh-wgfg
- [OSV] GHSA-jwhx-xcg6-8xhj
- [OSV] GHSA-pjjw-qhg8-p2p9
- [OSV] GHSA-q3qx-c6g2-7pw2
- [OSV] GHSA-qvrw-v9rv-5rjx
- [OSV] GHSA-v6wp-4m6f-gcjg
- [OSV] GHSA-xx9p-xxvh-7g8j
- [OSV] PYSEC-2021-76
- [OSV] PYSEC-2023-120
- [OSV] PYSEC-2023-246
- [OSV] PYSEC-2023-247
- [OSV] PYSEC-2023-250
- [OSV] PYSEC-2023-251
- [OSV] PYSEC-2024-24
- [OSV] PYSEC-2024-26

GitHub Metrics:
Stars: 15,204
Forks: 2,027
Open Issues: 249
Last Update: 2024-12-09 20:12:28+00:00

dataclasses:
-------------------
Version: 0.8
Monthly downloads: 18,805,604
No known vulnerabilities

GitHub Metrics:
Stars: 586
Forks: 53
Open Issues: 8
Last Update: 2024-07-11 16:14:35+00:00
```

Full report: [bettercheck-yourself.json](bettercheck-yourself.json)

## Installation


```bash
git clone https://github.com/rayking99/bettercheck
cd bettercheck
pip install -e .
```

## Usage

To get the commands automatically, you can run:
```bash
# View available commands and options
python -m bettercheck --help  
python -m bettercheck.check_yourself --help

# Example usage - check a package
python -m bettercheck requests --json
python -m bettercheck pandas --report md --with-deps
python -m bettercheck flask --debug

# Check this project
python -m bettercheck.check_yourself
python -m bettercheck.check_yourself --direct-only
```


Or more easily: 

```bash
# View available commands and options
bettercheck --help  
bettercheck pandas --report md --with-deps
bettercheck-yourself
bettercheck-deps pandas 
```


## Features

- Vulnerability scanning via OSV and CVE databases
- Package download statistics
- GitHub repository metrics
- Report generation (markdown/text)
- Detailed vulnerability descriptions
- Project dependency analysis

## License

MIT

## Roadmap

- Various tools to help understand open-source software development and dependencies. 

## Disclaimer

This is only a research tool. 

## Acknowledgements

This idea started with the video: Russ Cox at ACM SCORED: Open Source Supply Chain Security at Google [YouTube Video](https://www.youtube.com/watch?v=6H-V-0oQvCA)

Claude, Gemini, Llama and o1 all made contributions with the scope, code and understanding. 

## TODO

Recursive check to encompass entire supply-chain + visualisations. 