import argparse
import csv
import json
import re
import sys
import subprocess
from pathlib import Path
from tqdm import tqdm

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

def git_author(search_query=None):
    command = "git log --format='%aN' | sort -u"

    if search_query:
        command.extend(['--grep', search_query])

    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

def git_check(search_query=None):
    command = ['git', 'fsck', '--full', '--unreachable', '--lost-found']
    result = run_command(command).stdout.strip()
    
    if result:
        return result
    else:
        return "No issue found"

def git_deleted(search_query=None):
    command = ['git', 'log', '--diff-filter=D', '--name-only', '--pretty=format:']

    if search_query:
        command.extend(['--grep', search_query])

    return run_command(command)

def git_emails(repository_path='.'):
    command = ['git', 'log', '--pretty=format:%ae %ce']
    result = run_command(command)
    log_output = result.stdout

    emails = set()
    email_pattern = re.compile(r'[\w\.-]+@[\w\.-]+')
    emails = set(email_pattern.findall(log_output))

    if emails:
        for email in emails:
            print(f"{email}")
        return f"{len(emails)} emails found"
    else:
        return print("No emails found")

def trivy():
    command = ['trivy', 'repository', '.'] 
    return run_command(command).stdout

def virustotal():
    command =  ['git', 'ls-files']
    result = run_command(command)
    files = result.stdout.split('\n')
    found_match = False

    for file in tqdm(files, desc="Scanning files", unit="file"):
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
    command = ['gource']
    return run_command(command)

def export_to_json(data, filename):
    with open(filename, 'w') as json_file:
        json.dump(data, json_file, indent=4)

def export_to_csv(data, filename):
    with open(filename, 'w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        for row in data:
            csv_writer.writerow(row)

def main():
    is_git_repository()
    parser = argparse.ArgumentParser(description='A simple Git Forensic tool')
    parser.add_argument('--author', action='store_true', help='Display author link to a Git repository')
    parser.add_argument('--check', action='store_true', help='Run a Git file system check')
    parser.add_argument('--deleted', action='store_true', help='Display Git deleted files')
    parser.add_argument('--emails', action='store_true', help='Display associated emails with this Git repository')
    parser.add_argument('--trivy', action='store_true', help='Run Trivy on the repository')
    parser.add_argument('--virustotal', action='store_true', help='Run vt against all the hash')
    parser.add_argument('--visualize', action='store_true', help='Display Git visualization gui with gource')
    parser.add_argument('--search', metavar='search_query', help='Search for commits based on keywords or patterns in commit messages')
    parser.add_argument('--csv', metavar='filename.csv', help='Export data to CSV file')
    parser.add_argument('--json', metavar='filename.json', help='Export data to JSON file')

    args = parser.parse_args()

    if not any(vars(args).values()):
        parser.print_help()
    else:
        data = []

        search_query = args.search
 
        if args.author:
            data.append(git_author(search_query))

        if args.check:
            check_output = git_check()
            if check_output:
                print(check_output)

        if args.deleted:
            data.append(git_deleted(search_query))
        
        if args.emails:
            data.append(git_emails(search_query))

        if args.trivy:
            trivy_output = trivy()
            if trivy_output:
                print(f'{trivy_output}')
        
        if args.virustotal:
            virustotal()

        if args.visualize:
            visualize()

        if args.csv:
            export_to_csv(data, args.csv)
            print(f'Data exported to {args.csv} in CSV format')

        if args.json:
            export_to_json(data, args.json)
            print(f'Data exported to {args.json} in JSON format')

        if not args.csv and not args.json:
            for entry in data:
                print(entry)

if __name__ == "__main__":
    main()

