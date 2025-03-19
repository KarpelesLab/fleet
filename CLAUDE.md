# Fleet - Coding Guidelines

## Build & Test Commands
```bash
# Build
make                # Format and build
make deps           # Install dependencies

# Tests
make test           # Run all tests
go test -v github.com/KarpelesLab/fleet -run TestName  # Run specific test
```

## Code Style
- **Imports**: Standard library first, then third-party, alphabetically grouped
- **Formatting**: Use goimports (called in Makefile)
- **Types**: Strong typing with explicit interfaces, use pointers for mutable state
- **Error Handling**: Check errors with `if err != nil`, define package-level error variables
- **Naming**: CamelCase for exported items, lower camelCase for unexported
- **Concurrency**: Use Mutex/RWMutex for state protection, defer unlock after lock
- **Documentation**: Document "why" not "what" when appropriate
- **Functions**: Keep functions focused and reasonably sized

## Project Structure
Fleet is a Go library for distributed peer communication. Follow existing patterns for contributions.