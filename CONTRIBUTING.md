# Contributing to Odyssey

Thanks for your interest in contributing to Odyssey.

## Getting started

1. Fork the repository and clone your fork.
2. Build the project:

```bash
make                # Linux
# or
gcc -O2 -Wall -Wextra -Wpedantic -std=c11 -Iinclude -o bin/odyssey.exe src/*.c -lws2_32   # Windows (MinGW)
```

3. Run the tests (Linux):

```bash
for t in tests/smoke_*.sh; do
  echo "--- $t ---"
  bash "$t"
done
```

Some TUN-related tests require `CAP_NET_ADMIN`.

## How to contribute

- **Bug reports.** Open an issue with steps to reproduce, expected behavior, and actual behavior.
- **Feature requests.** Open an issue describing the use case and proposed solution.
- **Code changes.** Open a pull request against `main`. Keep PRs focused on a single change.

## Pull request guidelines

1. Make sure the project compiles without warnings on both Linux and Windows (MinGW).
2. Add or update smoke tests for any new functionality.
3. Update `README.md` if user-facing behavior changes.
4. One logical change per commit, with a clear commit message.
5. No compiled binaries in the PR. Only source code.

## Code style

- C11 standard (`-std=c11`).
- Compile clean with `-Wall -Wextra -Wpedantic`.
- Function and type names follow `od_module_action` / `od_module_type_t`.
- Check every return value and provide actionable error messages.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
