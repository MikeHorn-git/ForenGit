# Git Forensics Tool

![image](https://github.com/MikeHorn-git/ForenGit/assets/123373126/2b3befbb-f0f8-44db-b806-a610c72681b3)

# Optional Requirements
* [Exif](https://github.com/exiftool/exiftool)
* [Gource](https://github.com/acaudwell/Gource)
* [Trivy](https://github.com/aquasecurity/trivy)
* [VirusTotal](https://github.com/veetaw/vtcli) with API key

## Arch
```bash
yay -S perl-image-exiftool gource trivy vt-cli
```

# Features
* History
  * Blame
  * Branches
  * Commits
  * Deleted Objects

* Hunt
  * Author
  * Emails
  * Exif metadata
  * Geo data
  * Gpg keys
  * Network data

* Run
  * Git filesystem check
  * Git visualization tool
  * Trivy repository scanner
  * VirusTotal suspicious file scanner

# Usage
```bash
usage: ForenGit.py [-h] [-a] [-c] [-e] [-x] [-g] [-ha] [-hbl] [-hbr] [-hc] [-hd] [-ht] [-k] [-n] [-s] [-t] [-vt]
                   [-vi] [--csv filename.csv] [--json filename.json]

A simple Git Forensic tool

options:
  -h, --help            show this help message and exit
  -a, --author          Display author
  -c, --check           Run a filesystem check
  -e, --emails          Display emails
  -x, --exif            Display exif metadata
  -g, --geolocation     Display latitude and longitude data
  -ha, --history-all    Display all Git history
  -hbl, --history-blame
                        Display Git history branches
  -hbr, --history-branches
                        Display Git history branches
  -hc, --history-commits
                        Display Git history commits
  -hd, --history-deleted
                        Display Git history deleted objects
  -ht, --history-tags   Display Git history tags
  -k, --keys            Display gpg keys
  -n, --network         Display network informations
  -s, --statistic       Display commits numbers by author
  -t, --trivy           Run Trivy
  -vt, --virustotal     Run virustotal
  -vi, --visualize      Run gource
  --csv filename.csv    Export data to CSV file
  --json filename.json  Export data to JSON file
```
