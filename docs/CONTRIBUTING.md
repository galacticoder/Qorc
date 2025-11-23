# Contributing to Endtoend

First off, thank you for considering contributing to Endtoend! Contributions from everyone are welcome.

## Code of Conduct

This project and everyone participating in it is governed by the [Endtoend Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainer at galacticoderr@gmail.com.

## Getting Started

### Prerequisites

- **Node.js**: Ensure you have Node.js installed (v18+ recommended).
- **Git**: For version control.

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/galacticoder/end2end-chat-site.git
    cd end2end-chat-site
    ```

2.  **Install dependencies:**
    ```bash
    node scripts/install-deps.cjs --all
    ```

3.  **Generate Certificates:**
    ```bash
    node scripts/generate_ts_tls.cjs
    ```

4.  **Start the Application:**
    *   **Server:** `node scripts/start-server.cjs`
    *   **Client:** `node scripts/start-client.cjs`

## Development Workflow

1.  **Fork the repository** on GitHub.
2.  **Clone your fork** locally.
3.  **Create a branch** for your feature or bugfix:
    ```bash
    git checkout -b feature/your-feature-name
    ```
4.  **Make your changes.**
5.  **Run linting** to ensure code quality:
    ```bash
    npm run lint
    ```
6.  **Commit your changes** with descriptive commit messages.
7.  **Push to your fork:**
    ```bash
    git push origin feature/your-feature-name
    ```
8.  **Open a Pull Request** against the `main` branch of the original repository.

## Style Guide

*   **Linting:** This project uses ESLint. Please ensure your code passes linting before submitting a PR (`npm run lint`).
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
1.  Check existing issues to see if it has already been proposed.
2.  Open a new issue describing the enhancement and why it would be useful.

Thank you for contributing!
