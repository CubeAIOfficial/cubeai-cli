# CUBEAI-CLI - Enterprise ElizaOS Runtime

Enterprise-grade enhanced [ElizaOS](https://eliza.how/) CLI with sophisticated multi-tenant authentication, comprehensive API integration, and advanced isolation features designed for the CUBEAI platform. Each Cube instance operates this enhanced CLI within a completely isolated containerized environment featuring dedicated PostgreSQL databases, unique API endpoints, real-time WebSocket communication, and enterprise-level security controls.

## 🎯 What is CUBEAI-CLI?

CUBEAI-CLI is an enhanced version of the ElizaOS framework that adds:

- **Multi-tenant Authentication**: API key-based user access control
- **RESTful API**: HTTP endpoints for agent management and interaction
- **WebSocket Support**: Real-time communication with agents
- **Isolated Databases**: Each instance has its own PostgreSQL + pgvector database
- **User Management**: Integration with CUBEAI platform user system

## ⚡ Built on ElizaOS

Inherits all [ElizaOS](https://eliza.how/) capabilities:

- 🤖 **Agent Runtime**: Orchestrates agent behavior and state management
- ⚡ **Actions**: Executable capabilities for agent interactions
- 🔌 **Providers**: Real-time context for agent decisions
- 📚 **Services**: Cross-platform communication (Discord, Twitter, Telegram)
- 💾 **Vector Database**: Memories, relationships, and semantic search
- 🧠 **Knowledge System**: RAG for document processing

## 🚀 Quick Start

### Prerequisites

- **Node.js** 18+ and **Bun**
- **PostgreSQL** with **pgvector** extension
- **ElizaOS CLI**: `npm install -g @elizaos/cli`

### Development Setup

```bash
# Install dependencies
bun install

# Set up environment
cp .env.example .env
# Edit .env with your database and API configurations

# Start development server
bun run dev

# The CLI will be available at:
# - HTTP API: http://localhost:3001
# - WebSocket: ws://localhost:3001
```

### Environment Variables

```env
# Database Configuration
POSTGRES_URL=postgresql://user:password@localhost:5432/cubeai-cli-db

# Authentication
OWNER_API_KEYS=your_owner_api_key_here
ADMIN_API_KEYS=your_admin_api_key_here

# AI Models
USE_LOCAL_AI=true
OLLAMA_API_ENDPOINT=http://localhost:11434/api
OLLAMA_SMALL_MODEL=gemma2:2b
OLLAMA_MEDIUM_MODEL=gemma2:9b
OLLAMA_LARGE_MODEL=llama3.1:8b

# Server Configuration
SERVER_PORT=3001
LOG_LEVEL=debug
```

## 🔑 Authentication

CUBEAI-CLI uses API key-based authentication with two levels:

### Owner API Keys

- Full access to all agents and operations
- Can create, modify, and delete any agent
- Access to admin endpoints

### Admin API Keys

- Limited administrative access
- Can manage specific agents
- Read-only access to system information

### Usage

```bash
# Include API key in requests
curl -H "Authorization: Bearer your_api_key_here" \
     http://localhost:3001/api/agents
```

## 📡 API Endpoints

### Agent Management

```http
GET    /api/agents                    # List all agents
POST   /api/agents                    # Create new agent
GET    /api/agents/:id                # Get agent details
PUT    /api/agents/:id                # Update agent
DELETE /api/agents/:id                # Delete agent
```

### Conversations

```http
GET    /api/agents/:id/conversations  # Get conversation history
POST   /api/agents/:id/chat           # Send message to agent
GET    /api/agents/:id/memory         # Get agent memories
```

### System

```http
GET    /api/health                    # Health check
GET    /api/status                    # System status
GET    /api/models                    # Available AI models
```

## 🔌 WebSocket Interface

Real-time communication with agents:

```javascript
const ws = new WebSocket("ws://localhost:3001");

// Send message to agent
ws.send(
  JSON.stringify({
    type: "chat",
    agentId: "agent-uuid-here",
    message: "Hello, agent!",
    userId: "user-uuid-here",
  })
);

// Receive agent responses
ws.onmessage = (event) => {
  const response = JSON.parse(event.data);
  console.log("Agent response:", response);
};
```

## 🛠️ Development

### Project Structure

```
src/
├── index.ts              # Main entry point and server setup
├── plugin.ts             # CUBEAI plugin with auth middleware
├── auth-plugin.ts        # Authentication system
├── middleware/
│   └── auth.ts           # API key validation middleware
└── __tests__/            # Unit and integration tests
```

### Adding Custom Features

1. **Create new Actions**:

```typescript
// src/actions/customAction.ts
export const customAction: Action = {
  name: "CUSTOM_ACTION",
  similes: ["custom", "do_something"],
  description: "Performs a custom operation",
  handler: async (runtime, message, state) => {
    // Your action logic here
    return true;
  },
};
```

2. **Add new Providers**:

```typescript
// src/providers/customProvider.ts
export const customProvider: Provider = {
  get: async (runtime, message) => {
    return "Custom context information";
  },
};
```

3. **Register in plugin**:

```typescript
// src/plugin.ts
export const cubeaiPlugin: Plugin = {
  name: "cubeai",
  actions: [customAction],
  providers: [customProvider],
  // ...
};
```

## 🧪 Testing

### Unit Tests

```bash
# Run component tests
elizaos test

# Run specific test file
elizaos test --name "auth"
```

### Integration Tests

```bash
# Run E2E tests with live runtime
elizaos test --e2e
```

### Test Structure

- `__tests__/` - Unit and integration tests
- `e2e/` - End-to-end tests with full runtime
- `__tests__/utils/` - Test utilities and helpers

## 🔄 Multi-Tenant Isolation

Each CUBEAI-CLI instance provides complete isolation:

- **Database**: Separate PostgreSQL database per cube
- **Memory**: Isolated agent memories and conversations
- **Authentication**: Unique API keys per cube instance
- **Resources**: Dedicated compute and storage allocation
- **Networking**: Isolated network access and routing

## 🐳 Docker Deployment

```dockerfile
# Built for Docker deployment
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build
EXPOSE 3001
CMD ["npm", "start"]
```

## 📚 Integration with CUBEAI Platform

CUBEAI-CLI integrates with the main platform through:

- **User Database**: Validates users against platform database
- **Subscription Management**: Enforces limits based on user plans
- **Instance Metadata**: Reports status back to platform
- **Dynamic Provisioning**: Receives configuration from deployment system

## 🔗 Related Documentation

- **[ElizaOS Documentation](https://eliza.how/)** - Core framework docs
- **[CUBEAI Platform](../README.md)** - Main platform overview
- **[CUBEAI Client](../cubeai-client/README.md)** - Web application docs

---

**CUBEAI-CLI**: Your personalized ElizaOS instance in the cloud! 🧊⚡
