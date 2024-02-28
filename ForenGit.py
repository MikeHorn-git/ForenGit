#! /usr/bin/python3

#################################################################################
#MIT License                                                                    #
#                                                                               #
#Copyright (c) 2024 MikeHorn-git                                                #
#                                                                               #
#Permission is hereby granted, free of charge, to any person obtaining a copy   #
#of this software and associated documentation files (the "Software"), to deal  #
#in the Software without restriction, including without limitation the rights   #
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell      #
#copies of the Software, and to permit persons to whom the Software is          #
#furnished to do so, subject to the following conditions:                       #
#                                                                               #
#The above copyright notice and this permission notice shall be included in all #
#copies or substantial portions of the Software.                                #
#                                                                               #
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR     #
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,       #
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE    #
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER         #
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  #
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE  #
#SOFTWARE.                                                                      #
#################################################################################

import argparse
import csv
import json
import re
import shutil
import sys
import subprocess
from pathlib import Path

def is_git_repository(path='.'):
    git_dir = Path(path) / '.git'
    if git_dir.exists() and git_dir.is_dir():
        return True
    else:
        print(f'FATAL ERROR: {Path(path).resolve()} is not a Git repository')
        sys.exit(1)

def run_command(command):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result

def git_author():
    command = "git log --format='%aN' | sort -u"

    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

def git_check():
    command = ['git', 'fsck', '--full', '--unreachable', '--lost-found']
    result = run_command(command).stdout.strip()
    
    if result:
        return result
    else:
        return "No issue found"

def git_emails(repository_path='.'):
    command = ['git', 'log', '--pretty=format:%ae %ce']
    result = run_command(command)
    log_output = result.stdout

    emails = set()
    email_pattern = re.compile(r'[\w\.-]+@[\w\.-]+')
    emails = set(email_pattern.findall(log_output))

    return emails

def git_geolocation():
    command = ['git', 'grep -E', "'[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?)\s*[,]\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)'", '--', "'*.txt'", "'*.md'", "'*.json'"]

    return run_command(command).stdout

def git_gpg_keys():
    all_gpg_keys = []

    # Method 1: Extract GPG keys from commit signatures
    command_method_1 = ['git', 'log', '--show-signature', '--format="%G? %GS"']
    result_method_1 = run_command(command_method_1).stdout
    gpg_keys_method_1 = re.findall(r'(?<=G )[A-Fa-f0-9]+', result_method_1)
    all_gpg_keys.extend(gpg_keys_method_1)

    # Method 2: Extract GPG keys from commit messages
    command_method_2 = ['git', 'log', "--grep='[A-F0-9]\{16,\}'"]
    result_method_2 = run_command(command_method_2).stdout
    gpg_keys_method_2 = result_method_2.split()
    all_gpg_keys.extend(gpg_keys_method_2)

    # Method 3: Extract GPG keys from files with .asc or .gpg extension
    command_method_3 = ['git', 'ls-files', '|', 'grep', '-E', '\.asc$|\.gpg$']
    result_method_3 = run_command(command_method_3).stdout
    gpg_keys_method_3 = result_method_3.split()
    all_gpg_keys.extend(gpg_keys_method_3)

    # Method 4: Extract GPG keys from commit patches
    command_method_4 = ['git', 'log', '-p', '|', 'grep', '-B', '2', '"-----BEGIN PGP SIGNATURE-----"']
    result_method_4 = run_command(command_method_4).stdout
    gpg_keys_method_4 = re.findall(r'(?<=G )[A-Fa-f0-9]+', result_method_4)
    all_gpg_keys.extend(gpg_keys_method_4)

    # Method 5: Extract GPG keys from files using '-----BEGIN PGP PUBLIC KEY BLOCK-----'
    command_method_5 = ['git', 'grep', '-E', '--ignore-case', '-----BEGIN PGP PUBLIC KEY BLOCK-----']
    result_method_5 = run_command(command_method_5).stdout
    gpg_keys_method_5 = re.findall(r'(?<=G )[A-Fa-f0-9]+', result_method_5)
    all_gpg_keys.extend(gpg_keys_method_5)

    return all_gpg_keys

def git_history_branches():
    command = ['git', 'for-each-ref', '--sort=-committerdate', '--format', '%(refname:short) %(committername) %(committerdate:short) %(committerdate:relative)']

    result = run_command(command).stdout

    branches = []

    for line in result.strip().split('\n'):
        parts = line.split()
        branch_name = parts[0]
        committer_name = parts[1]
        commit_date_short = parts[2]
        commit_date_relative = ' '.join(parts[3:])

        branches.append(f"{branch_name} - {committer_name}, {commit_date_short} {commit_date_relative}")

    return branches

def git_history_blame():
    command = "git ls-files | xargs -I {} git blame --pretty=format:'%h - %an %ad : %s' --date=iso {}"
    
    result = subprocess.run(command, shell=True, capture_output=True)

    return result.stdout.decode("utf-8", errors="replace")

def git_history_commits():
    command = ['git', 'log', '--pretty=format:%h - %an, %ad : %s', '--date=iso']

    return run_command(command).stdout

def git_history_deleted():
    command = ['git', 'log', '--diff-filter=D', '--name-only', '--pretty=format:%h - %an, %ad : %s']

    result = run_command(command).stdout
    commits = result.strip().split('\n\n')

    formatted_commits = '\n'.join(commits)

    return formatted_commits

def git_history_tags():
    command = ['git', 'for-each-ref', '--sort=-taggerdate', '--format', '%(refname:short) %(taggername) %(taggerdate:iso)']

    result = run_command(command).stdout

    tags = []
    for line in result.strip().split('\n'):
        parts = line.split()
        tag_name = parts[0]
        tagger_name = parts[1] if len(parts) > 1 else 'Unknown Tagger'
        creation_date = parts[2] if len(parts) > 2 else 'Unknown Date'
        tags.append(f"{tag_name} - {tagger_name}, {creation_date}")

    return tags

def git_network():
    command_ip = ['git', 'grep', '-E', '--ignore-case', r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b']
    result_ip = run_command(command_ip).stdout

    if result_ip:
        print(f'Possible IP addresses found: {result_ip}')
        print("---------------------")
    else:
        print("No IP addresses found")
        print("---------------------")

    command_mac = ['git', 'grep', '-E', '--ignore-case', r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}']
    result_mac = run_command(command_mac).stdout

    if result_mac:
        print(f'Possible MAC addresses found: {result_mac}')
        print("---------------------")
    else:
        print("No MAC addresses found")
        print("---------------------")

    command_ssh = ['git', 'grep', '-E', '--ignore-case', r'ssh-[a-z]+']
    result_ssh = run_command(command_ssh).stdout

    if result_ssh:
        print(f'Possible ssh information found: {result_ssh}')
    else:
        print("No SSH information found")

def git_statistic():
    command = ['git', 'shortlog', '-s', '-n']
    return run_command(command).stdout

def exif():
    tool = ["exiftool"]

    if shutil.which(tool[0]) is None:
        print(f"Error: {tool[0]} command not found.")
        return None

    command = "git ls-files | grep -E '\.(gif|jpg|jpeg|png|tif|wav|webp)$' | xargs -I {} exiftool {}"

    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

def trivy():
    tool = ["trivy"]

    if shutil.which(tool[0]) is None:
        print(f"FATAL ERROR: {tool[0]} command not found.")
        return None

    command = ['trivy', 'repository', '.'] 
    return run_command(command).stdout

def virustotal():
    tool = ["vt"]

    if shutil.which(tool[0]) is None:
        print(f"FATAL ERROR: {tool[0]} command not found.")
        return None

    command =  ['git', 'ls-files']
    result = run_command(command)
    files = result.stdout.split('\n')
    found_match = False

    for file in files:
        if file:
            command = ['git', 'hash-object', file]
            result = run_command(command)
            file_hash = result.stdout.strip()
            vt_command = ['vt', 'file', file_hash]
            vt_result = run_command(vt_command)
            
            if vt_result.stdout:
                print(f"Results for {file}:")
                print(vt_result.stdout)
                print()
                found_match = True

    if not found_match:
        print("No matches found")

def visualize():
    tool = ["gource"]

    if shutil.which(tool[0]) is None:
        print(f"FATAL ERROR: {tool[0]} command not found.")
        return None

    command = ['gource']
    return run_command(command)

def export_data(data, filename=None, file_type=None):
    if filename:
        if file_type == 'csv':
            with open(filename, 'w', newline='') as csv_file:
                csv_writer = csv.writer(csv_file)
                for entry in data.split('\n'):
                                        csv_writer.writerow([entry.strip()])
            print(f'Data exported to {filename} in CSV format')
        elif file_type == 'json':
            with open(filename, 'w') as json_file:
                json.dump(data, json_file, indent=4)
            print(f'Data exported to {filename} in JSON format')
    else:
        for entry in data:
            print(entry)

def main():
    is_git_repository()
    parser = argparse.ArgumentParser(description='A simple Git Forensic tool')
    parser.add_argument('-a', '--author', action='store_true', help='Display author')
    parser.add_argument('-c', '--check', action='store_true', help='Run a filesystem check')
    parser.add_argument('-e', '--emails', action='store_true', help='Display emails')
    parser.add_argument('-x', '--exif', action='store_true', help='Display exif metadata')
    parser.add_argument('-g', '--geolocation', action='store_true', help='Display latitude and longitude data')
    parser.add_argument('-ha', '--history-all', action='store_true', help='Display all Git history')
    parser.add_argument('-hbl', '--history-blame', action='store_true', help='Display Git history branches')
    parser.add_argument('-hbr', '--history-branches', action='store_true', help='Display Git history branches')
    parser.add_argument('-hc', '--history-commits', action='store_true', help='Display Git history commits')
    parser.add_argument('-hd', '--history-deleted', action='store_true', help='Display Git history deleted objects')
    parser.add_argument('-ht', '--history-tags', action='store_true', help='Display Git history tags')
    parser.add_argument('-k', '--keys', action='store_true', help='Display Gpg keys')
    parser.add_argument('-n', '--network', action='store_true', help='Display network informations')
    parser.add_argument('-s', '--statistic', action='store_true', help='Display commits numbers by author')
    parser.add_argument('-t', '--trivy', action='store_true', help='Run Trivy')
    parser.add_argument('-vt', '--virustotal', action='store_true', help='Run Virustotal')
    parser.add_argument('-vi', '--visualize', action='store_true', help='Run Gource') 
    parser.add_argument('--csv', metavar='filename.csv', help='Export data to CSV file for history commands only')
    parser.add_argument('--json', metavar='filename.json', help='Export data to JSON file for history commands only')

    args = parser.parse_args()

    if not any(vars(args).values()):
        parser.print_help()
    elif (args.csv or args.json) and not any([args.history_all, args.history_blame, args.history_branches, args.history_commits, args.history_deleted, args.history_tags]):
        print("FATAL ERROR: --csv or --json must be used with history command")
    else:
        data = []
 
        if args.author:
            data.append(git_author())

        if args.check:
            check_output = git_check()
            if check_output:
                print(check_output)
 
        if args.emails:
            emails_output = git_emails()
            if emails_output:
                for email in emails_output:
                    print(f"{email}")
            else:
                return print("No emails found")
        
        if args.exif:
            exif_output = exif()
            if exif_output:
                print(f'{exif_output}')
            else:
                print("No exif metadata found")

        if args.geolocation:
            geolocation_output = git_geolocation()
            if geolocation_output:
                print(f'Possible geolocation data found: {geolocation_output}')
            else:
                print("No geolocation data found")

        if args.history_all:
            if git_history_blame():
                print("Blame:")
                print(f'{git_history_blame()}')

            if git_history_branches():
                print("Branches:")
                for branch in git_history_branches():
                    print(f'{branch}')

            if git_history_commits():
                print("Commits:")
                print(f'{git_history_commits()}\n')
            
            if git_history_deleted():
                print("Deleted:")
                print(f'{git_history_deleted()}\n')

            if git_history_tags():
                print("Tags:")
                for tag in git_history_tags():
                    print(f'{tag}')
        
        if args.history_blame:
            if git_history_blame():
                if args.csv:
                    export_data(git_history_blame(), args.csv, 'csv')
                elif args.json:
                    export_data(git_history_blame(), args.json, 'json')
                else:
                    print(git_history_blame()) 

        if args.history_branches:
            if git_history_branches():
                if args.csv:
                    export_data(git_history_branches(), args.csv, 'csv')
                elif args.json:
                    export_data(git_history_branches(), args.json, 'json')
                else:
                    print(git_history_branches()) 

        if args.history_commits:
            if git_history_commits():
                if args.csv:
                    export_data(git_history_commits(), args.csv, 'csv')
                elif args.json:
                    export_data(git_history_commits(), args.json, 'json')
                else:
                    print(git_history_commits())

        if args.history_deleted:
            if git_history_deleted():
                if args.csv:
                    export_data(git_history_deleted(), args.csv, 'csv')
                elif args.json:
                    export_data(git_history_deleted(), args.json, 'json')
                else:
                    print(git_history_deleted())

        if args.history_tags:
            if git_history_tags():
                if args.csv:
                    export_data(git_history_tags(), args.csv, 'csv')
                elif args.json:
                    export_data(git_history_tags(), args.json, 'json')
                else:
                    print(git_history_tags())

        if args.keys:
            gpg_output = git_gpg_keys()
            if gpg_output:
                print(f'{gpg_output}')
            else:
                print("No gpg keys found")

        if args.network:
            git_network()

        if args.statistic:
            statistic_output = git_statistic()
            if statistic_output:
                print(f'{statistic_output}')

        if args.trivy:
            trivy_output = trivy()
            if trivy_output:
                print(f'{trivy_output}')
        
        if args.virustotal:
            virustotal()

        if args.visualize:
            visualize()
 
if __name__ == "__main__":
    main()
