# Contributing

## Workflow

1. Fork the repository.
2. Create a feature branch (`git switch -c feat/my-thing`).
3. Make your changes.
4. Run the tests and ensure they pass.
5. Format your code with `clang-format` (the project uses `.clang-format` at the root).
6. Open a pull request.

## Code style

- Follow the existing style enforced by `.clang-format`.
- Keep the header-only hooker (`syringe_hook.h`) self-contained — no external dependencies beyond libc.
- Avoid breaking the single-TU design of `syringe_hook.h`.
- New platform backends should follow the pattern in `include/public/hook/arch/` and `src/arch`.

## Commit conventions

- Use conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`.
- Keep commits atomic — one logical change per commit.
- Reference issues or PRs in the body when relevant.

## Pull requests

- Keep PRs focused on a single concern.
- Update docs if the API surface changes.
- Add tests for new functionality.
- Verify no regressions on both x86_64 and aarch64 (QEMU user-mode is sufficient).
