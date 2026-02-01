# Hello Skill

A simple greeting skill that demonstrates secure agent operation.

## Description

This skill allows the agent to greet users and perform basic file operations within the allowed workspace.

## Capabilities

- Generate personalized greetings
- Read files from the workspace
- Write greeting logs to the output directory

## Usage

Ask the agent:
- "Say hello to Alice"
- "Read the welcome message from data/welcome.txt"
- "Log a greeting for Bob"

## Examples

### Basic Greeting

**User:** Say hello to the team

**Agent:** Hello, team! Welcome to the secure agent demonstration.

### File Operations

**User:** Read the project description

**Agent:** I'll read the README file for you.
```
[Uses read_file tool - verified by hushclaw]
```

### Secure Logging

**User:** Log a greeting for today

**Agent:** I'll create a greeting log.
```
[Uses write_file to ./output/greeting.log - verified by hushclaw]
```

## Security Notes

This skill operates within the hushclaw security boundary:

- File reads are restricted to the workspace (`./**`)
- File writes are restricted to `./output/**`
- No network calls are made by this skill
- No shell commands are executed

All operations are logged to the audit receipt.
