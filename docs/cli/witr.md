## witr

Why is this running?

### Synopsis

witr explains why a process or port is running by tracing its ancestry.

```
witr [process name...] [flags]
```

### Examples

```

  # Inspect a running process by name
  witr nginx

  # Look up a process by PID
  witr --pid 1234

  # Find the process listening on a specific port
  witr --port 5432

  # Find the process holding a file open
  witr --file /var/lib/dpkg/lock

  # Inspect a container by name
  witr --container redis

  # Inspect a process by name with exact matching (no fuzzy search)
  witr bun --exact

  # Show the full process ancestry (who started whom)
  witr postgres --tree

  # Show only warnings (suspicious env, arguments, parents)
  witr docker --warnings

  # List zombie processes, grouped by the parent that should collect them
  witr --zombies

  # List processes that look left behind (deleted binary or directory, stopped, detached copies)
  witr --sus

  # Display only environment variables of the process
  witr node --env

  # Short, single-line output (useful for scripts)
  witr sshd --short

  # Disable colorized output (CI or piping)
  witr redis --no-color

  # Output machine-readable JSON
  witr chrome --json

  # Show extended process information (memory, I/O, file descriptors)
  witr mysql --verbose

  # Combine flags: inspect port, show environment variables, output JSON
  witr --port 8080 --env --json

  # Multiple inputs
  witr nginx node
  witr --port 8080 --port 3000
  witr --pid 1234 --pid 5678

  # Mixed inputs
  witr nginx --pid 1234 --port 8080

```

### Options

```
  -c, --container strings          container(s) to look up (repeatable)
      --env[=true|false]           show environment variables for the process
  -x, --exact[=true|false]         use exact name matching (no substring search)
  -f, --file strings               file(s) held open by a process (repeatable)
  -h, --help[=true|false]          help for witr
  -i, --interactive[=true|false]   interactive mode (TUI)
      --json[=true|false]          show result as JSON
      --no-color[=true|false]      disable colorized output
  -p, --pid strings                pid(s) to look up (repeatable)
  -o, --port strings               port(s) to look up (repeatable)
  -s, --short[=true|false]         show only ancestry
      --suspects[=true|false]      list processes that look left behind (alias --sus; --verbose includes weak signals)
  -t, --tree[=true|false]          show only ancestry as a tree
      --verbose[=true|false]       show extended process information
      --warnings[=true|false]      show only warnings
      --zombies[=true|false]       list zombie processes grouped by the parent that has not collected them
```

