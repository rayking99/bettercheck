# BETTERCHECK

Better than nothing.

## What is it?

A CLI tool that helps evaluate Python packages for security concerns before installing them. Performs checks against multiple vulnerability databases and provides useful metrics about package health.

### bettercheck Analysis of bettercheck
```sh
(.venv) ... % bettercheck-yourself

Analyzing requests...

Analyzing click...

Analyzing packaging...

Analyzing pygithub...

Analyzing pypistats...

Report saved to: bettercheck/reports/bettercheck-20241209_194700.json

=== Dependencies Security Analysis ===

Total packages analyzed: 5
Total vulnerabilities found: 11


requests:
-------------------
Version: 2.32.3
Monthly downloads: 571,358,961
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
GitHub stars: 52,268
Last update: 2024-11-10 16:18:37+00:00

click:
-------------------
Version: 8.1.7
Monthly downloads: 254,831,371
No known vulnerabilities

packaging:
-------------------
Version: 24.2
Monthly downloads: 504,346,332
No known vulnerabilities
GitHub stars: 627
Last update: 2024-12-01 15:33:46+00:00

pygithub:
-------------------
Version: 2.5.0
Monthly downloads: 35,119,161
No known vulnerabilities
GitHub stars: 7,068
Last update: 2024-12-04 08:56:01+00:00

pypistats:
-------------------
Version: 1.7.0
Monthly downloads: 25,492
No known vulnerabilities
GitHub stars: 200
Last update: 2024-12-08 11:29:21+00:00

```

Full report: [bettercheck-yourself.json](bettercheck-yourself.json)

## Installation


```bash
git clone https://github.com/rayking99/bettercheck
cd bettercheck
pip install -e .
```

## Usage

Check a single package:
```bash
bettercheck requests
```

Generate a report:
```bash
bettercheck requests --report md
```

Practice what you preach. 
```bash
bettercheck-yourself
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