# Contributing to Qor-Chat

Thank you for considering contributing to Qor-Chat! Contributions from everyone are welcome.

## Code of Conduct

This project and everyone participating in it is governed by the [Qor Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainer at galacticoderr@gmail.com.

## Getting Started

### Prerequisites

- **Node.js**: Ensure you have Node.js installed (v18+ recommended).
- **Git**: For version control.

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/galacticoder/Qor-Chat.git
    cd Qor-Chat
    ```

2.  **Install dependencies:**
    ```bash
    node scripts/install-deps.cjs --server
    node scripts/install-deps.cjs --client
    ```
    Run both. The `--all` preset covers the server and edge toolchain only, it
    does not install pnpm, Rust, or Tauri, so the client will not build without
    `--client`. The installer targets Linux.

3.  **Generate Certificates:**
    ```bash
    node scripts/generate_tls.cjs
    ```

4.  **Set a server password:** add `SERVER_PASSWORD` (12-512 characters) to
    `.env`. The launchers generate the remaining required values on first run.
    See [ENVIRONMENT_VARIABLES.md](ENVIRONMENT_VARIABLES.md).

5.  **Start the Application:**
    *   **Server:** `node scripts/start-docker.cjs server`
    *   **Client:** `node scripts/start-client.cjs`

## Development Workflow

1.  **Fork the repository** on GitHub.
2.  **Clone your fork** locally.
3.  **Create a branch** for your feature or bugfix:
    ```bash
    git checkout -b feature/your-feature-name
    ```
4.  **Make your changes.**
5.  **Run linting and type checking:**
    ```bash
    pnpm lint
    pnpm exec tsc -p tsconfig.app.json --noEmit
    ```
    Always pass `-p tsconfig.app.json`. The root `tsconfig.json` has an empty
    `files` array, so a bare `tsc` type checks nothing and exits 0.
6.  **Run the security tests** if you touched anything under `server/`:
    ```bash
    pnpm test:security
    ```
7.  **Commit your changes** with descriptive commit messages.
8.  **Push to your fork:**
    ```bash
    git push origin feature/your-feature-name
    ```
9.  **Open a Pull Request** against the `main` branch of the original repository.

## Style Guide

*   **Linting:** This project uses ESLint. Please ensure your code passes linting before submitting a PR (`pnpm lint`). The project is pnpm-only, `pnpm-lock.yaml` is the committed lockfile.
*   **Formatting:** Try to follow the existing code style.
*   **TypeScript:** Use TypeScript for all new UI code (`.ts`, `.tsx`).

## Reporting Bugs

If you find a bug, please create an issue on GitHub. Include:
*   A clear title and description.
*   Steps to reproduce the bug.
*   Expected vs. actual behavior.
*   Screenshots if applicable.
*   Your OS and environment details.

## Suggesting Enhancements

I love hearing about new ideas. If you have a suggestion:
1.  Check existing issues to see if it has already been posted.
2.  Open a new issue describing the enhancement and why it would be useful.

Thank you for contributing!
