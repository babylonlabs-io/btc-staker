# BTC-Staker Project Overview

## What is BTC-Staker?

BTC-Staker is a Bitcoin staking application that enables users to stake their Bitcoin with the Babylon chain to earn rewards while helping secure the network. It provides a complete toolset for managing Bitcoin staking operations, including delegation creation, unbonding, and withdrawal functionality.

## Architecture

### Core Components

**1. Staker Daemon (`stakerd`)**
- Main service that manages Bitcoin staking operations
- Runs HTTP JSON-RPC server for client interactions
- Monitors Bitcoin network and Babylon chain events
- Handles transaction lifecycle management
- Provides authentication via basic auth (environment variables)

**2. Staker CLI (`stakercli`)**
- Command-line interface for interacting with the daemon
- Supports staking, unbonding, withdrawal, and transaction management
- Includes admin utilities and Phase 1 migration tools
- Authentication credentials loaded from environment variables

### Key Features

**Multi-Chain Integration**
- **Bitcoin Network**: Direct transaction creation, signing, and broadcasting
- **Babylon Chain**: Delegation submission and parameter querying
- **Cross-Chain State Management**: Synchronizes state between networks

**Transaction Lifecycle**
1. **Creation**: User creates staking transaction via CLI/API
2. **Signing**: Transaction signed with wallet private key  
3. **Delegation**: Sent to Babylon with proof-of-possession
4. **Activation**: Covenant signs and activates delegation
5. **Monitoring**: App monitors for state changes
6. **Completion**: Unbonding or expiry withdrawal

**State Management**
- **PENDING**: Sent to Babylon, awaiting covenant signatures
- **VERIFIED**: Confirmed on Bitcoin, awaiting activation
- **ACTIVE**: Live delegation receiving rewards
- **EXPIRED**: Past timelock, eligible for withdrawal

## Getting Started

### Prerequisites
- Go 1.23+
- Running Bitcoin node (bitcoind or btcd) with legacy wallet
- Babylon keyring with funds
- Basic authentication environment variables

### Installation
```bash
# Clone and build
git clone https://github.com/babylonlabs-io/btc-staker.git
cd btc-staker
make install

# Set up environment variables
export BTCSTAKER_USERNAME=your_username
export BTCSTAKER_PASSWORD=your_password
```

### Configuration
Initialize configuration:
```bash
stakercli admin dump-config --config-file-dir /path/to/config
```

Edit `stakerd.conf` to configure:
- Bitcoin node connection (RPC, wallet settings)
- Babylon chain parameters (RPC/gRPC endpoints, keys)
- Network settings (mainnet/testnet/signet)

### Running the System
```bash
# Start the daemon
stakerd

# Use CLI to interact (in another terminal)
stakercli daemon stake --staker-address <address> --staking-amount 1000000 --finality-providers-pks <pk> --staking-time 10000
```

## Key Commands

### Staking Operations
- `stakercli daemon stake` - Create new staking transaction
- `stakercli daemon unbond` - Initiate unbonding process
- `stakercli daemon unstake` - Withdraw funds after timelock
- `stakercli daemon list-staking-transactions` - View transaction history
- `stakercli daemon withdrawable-transactions` - View available withdrawals

### Information Queries
- `stakercli daemon babylon-finality-providers` - List active finality providers
- `stakercli daemon list-outputs` - Show available Bitcoin UTXOs
- `stakercli daemon staking-details` - Get specific transaction details

### Phase 1 Migration
- `stakercli daemon stake-from-phase1` - Convert Phase 1 BTC to Babylon delegation

## Development

### Project Structure
```
btc-staker/
├── cmd/                    # Main executables
│   ├── stakerd/           # Daemon main
│   └── stakercli/         # CLI main
├── staker/                # Core staking logic
├── stakerservice/         # HTTP/RPC service layer
├── babylonclient/         # Babylon chain integration
├── walletcontroller/      # Bitcoin wallet abstraction
├── stakercfg/            # Configuration management
├── stakerdb/             # Database layer
├── metrics/              # Prometheus metrics
└── types/                # Shared type definitions
```

### Testing
```bash
# Run unit tests
make test

# Run end-to-end tests
make test-e2e
```

### Building
```bash
# Build binaries
make build

# Build Docker image
make build-docker
```

## Security Considerations

- Uses basic authentication for API access
- Secure key management through wallet controller
- Input validation and sanitization
- Private keys never leave the local wallet
- Comprehensive error handling and recovery

## Documentation

- **README.md**: Detailed setup and usage instructions
- **CONTRIBUTING.md**: Development guidelines
- **CHANGELOG.md**: Version history and changes
- **docs/**: Phase 1 staking documentation

## Support

- GitHub Issues: Report bugs and feature requests
- Code Repository: https://github.com/babylonlabs-io/btc-staker
- Documentation: Built-in help via `stakercli --help`

## Build Information

- **Language**: Go 1.23+
- **Dependencies**: Bitcoin libraries (btcsuite), Cosmos SDK, Babylon chain
- **Build Tools**: Make, Docker, Go modules
- **Testing**: Unit tests, integration tests, E2E tests
- **Metrics**: Prometheus metrics support