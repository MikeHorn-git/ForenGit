import argparse
import csv
import json
import re
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

def run_git_command(command):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result

def git_blame(filename, search_query=None):
    command = ['git', 'blame']

    if search_query:
        command.extend(['-S', " ".join(search_query)])

    command.append(filename)
    return run_git_command(command).stdout

def git_branches(search_query=None):
    command = ['git', 'branch', '--all']

    if search_query:
        command.extend(['--contains', search_query])

    return run_git_command(command).stdout

def git_deleted(search_query=None):
    command = ['git', 'log', '--diff-filter=D', '--summary']

    if search_query:
        command.extend(['--grep', search_query])

    return run_git_command(command).stdout

def git_emails(repository_path='.'):
    command = ['git', 'log', '--pretty=format:%ae %ce']
    result = run_git_command(command)
    log_output = result.stdout

    emails = set()
    email_pattern = re.compile(r'[\w\.-]+@[\w\.-]+')
    emails = set(email_pattern.findall(log_output))

    for email in emails:
        print(f"- {email}")

def git_history(search_query=None):
    command = ['git', 'log', '--name-status']

    if search_query:
        command.extend(['--grep', search_query])

    return run_git_command(command).stdout

def git_log(search_query=None):
    command = ['git', 'log', '--all', '--graph', '--oneline', '--decorate']

    if search_query:
        command.extend(['--grep', search_query])

    return run_git_command(command).stdout

def git_reflog(search_query=None):
    command = ['git', 'reflog']

    if search_query:
        command.extend(['--grep', search_query])

    return run_git_command(command).stdout

def gource():
    return subprocess.run(['gource'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def trivy():
    return subprocess.run(['trivy', 'repository', '.'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

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
    parser.add_argument('--blame', metavar=('filename', 'search_query'), nargs='+', help='Run Git blame on a specific file')
    parser.add_argument('--branches', action='store_true', help='Display information about branches')
    parser.add_argument('--deleted', action='store_true', help='Display Git deleted files')
    parser.add_argument('--emails', action='store_true', help='Display associated emails with this Git repository')
    parser.add_argument('--gource', action='store_true', help='Display Git visualization gui')
    parser.add_argument('--history', action='store_true', help='Display Git log with name-status')
    parser.add_argument('--log', action='store_true', help='Display Git log')
    parser.add_argument('--reflog', action='store_true', help='Display Git reflog')
    parser.add_argument('--trivy', action='store_true', help='Run Trivy on the repository')
    parser.add_argument('--search', metavar='search_query', help='Search for commits based on keywords or patterns in commit messages')
    parser.add_argument('--csv', metavar='filename.csv', help='Export data to CSV file')
    parser.add_argument('--json', metavar='filename.json', help='Export data to JSON file')

    args = parser.parse_args()

    if not any(vars(args).values()):
        parser.print_help()
    else:
        data = []

        search_query = args.search

        if args.blame:
            filename, blame_search_query = args.blame
            data.append(git_blame(filename, blame_search_query or search_query))

        if args.branches:
            data.append(git_branches(search_query))

        if args.deleted:
            data.append(git_deleted(search_query))
        
        if args.emails:
            data.append(git_emails(search_query))

        if args.history:
            data.append(git_history(search_query))

        if args.log:
            data.append(git_log(search_query))

        if args.reflog:
            data.append(git_reflog(search_query))

        if args.gource:
            gource()

        if args.trivy:
            trivy_output = trivy()
            if trivy_output.stdout:
                print(f'{trivy_output.stdout}')

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

