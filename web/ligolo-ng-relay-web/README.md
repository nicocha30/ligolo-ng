# Ligolo-ng Relay WebUI

Ligolo-ng Relay WebUI is a web application providing an intuitive user interface for **Ligolo-ng Relay**, an advanced tunneling/pivoting solution using a TUN interface. This UI simplifies the management and control of tunnels established by Ligolo-ng Relay.

## Features

- **Agent visualization**: Displays a list of connected agents with their respective details.
- **Tunnel management**: Enables easy creation, monitoring, and termination of tunnels.
- **Network information**: Provides details on configured network interfaces and routes.

## Prerequisites

- **Node.js**: Ensure Node.js is installed on your machine.
- **Ligolo-ng Relay**: The Ligolo-ng Relay proxy must be operational on your system.

## Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/allsmog/ligolo-ng-relay.git
   cd ligolo-ng-relay/web/ligolo-ng-relay-web
   ```

2. **Install dependencies**:

   ```bash
   npm install
   ```

## Development

To start the application in development mode with hot-reloading:

```bash
npm run dev
```

Then, access the UI via `http://localhost:3000` (default).

## Production Build

To create an optimized production build:

```bash
npm run build
```

The generated files will be available in the `dist/` directory.

## Deployment

After building, serve the static files from the `dist/` directory using your preferred server (e.g., `serve`, `nginx`, etc.).

## Contribution

Contributions are welcome! Please submit issues and pull requests on the GitHub repository.

## License

This project is licensed under the [GPL-3.0](https://github.com/nicocha30/ligolo-ng/blob/master/LICENSE).

---

*Note: This project is a user interface for Ligolo-ng Relay. For upstream background, see the original [Ligolo-ng repository](https://github.com/nicocha30/ligolo-ng).*
