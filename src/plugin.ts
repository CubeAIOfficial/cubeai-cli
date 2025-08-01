import type { Plugin } from "@elizaos/core";
import {
  type Action,
  type Agent,
  AgentStatus,
  type Content,
  type GenerateTextParams,
  type HandlerCallback,
  type IAgentRuntime,
  type Memory,
  ModelType,
  type Provider,
  type ProviderResult,
  Service,
  type State,
  logger,
} from "@elizaos/core";
import { z } from "zod";
import { getAuthConfig, healthCheck } from "./middleware/auth.js";
import { AuthService } from "./services/auth-service.js";

/**
 * Define the configuration schema for the plugin with the following properties:
 *
 * @param {string} EXAMPLE_PLUGIN_VARIABLE - The name of the plugin (min length of 1, optional)
 * @returns {object} - The configured schema object
 */
const configSchema = z.object({
  EXAMPLE_PLUGIN_VARIABLE: z
    .string()
    .min(1, "Example plugin variable is not provided")
    .optional()
    .transform((val) => {
      if (!val) {
        console.warn("Warning: Example plugin variable is not provided");
      }
      return val;
    }),
  // Auth configuration
  OWNER_API_KEYS: z.string().optional(),
  ADMIN_API_KEYS: z.string().optional(),
  CUBEAI_API_ENDPOINT: z.string().url().optional(),
  CUBEAI_INSTANCE_ID: z.string().optional(),
});

/**
 * Example HelloWorld action
 * This demonstrates the simplest possible action structure
 */
/**
 * Represents an action that responds with a simple hello world message.
 *
 * @typedef {Object} Action
 * @property {string} name - The name of the action
 * @property {string[]} similes - The related similes of the action
 * @property {string} description - Description of the action
 * @property {Function} validate - Validation function for the action
 * @property {Function} handler - The function that handles the action
 * @property {Object[]} examples - Array of examples for the action
 */
const helloWorldAction: Action = {
  name: "HELLO_WORLD",
  similes: ["GREET", "SAY_HELLO"],
  description: "Responds with a simple hello world message",

  validate: async (
    _runtime: IAgentRuntime,
    _message: Memory,
    _state: State
  ): Promise<boolean> => {
    // Always valid
    return true;
  },

  handler: async (
    _runtime: IAgentRuntime,
    message: Memory,
    _state: State,
    _options: any,
    callback: HandlerCallback,
    _responses: Memory[]
  ) => {
    try {
      logger.info("Handling HELLO_WORLD action");

      // Simple response content
      const responseContent: Content = {
        text: "hello world!",
        actions: ["HELLO_WORLD"],
        source: message.content.source,
      };

      // Call back with the hello world message
      await callback(responseContent);
    } catch (error) {
      logger.error("Error in HELLO_WORLD action:", error);
      throw error;
    }
  },

  examples: [
    [
      {
        name: "{{name1}}",
        content: {
          text: "Can you say hello?",
        },
      },
      {
        name: "{{name2}}",
        content: {
          text: "hello world!",
          actions: ["HELLO_WORLD"],
        },
      },
    ],
  ],
};

/**
 * Example Hello World Provider
 * This demonstrates the simplest possible provider implementation
 */
const helloWorldProvider: Provider = {
  name: "HELLO_WORLD_PROVIDER",
  description: "A simple example provider",

  get: async (
    _runtime: IAgentRuntime,
    _message: Memory,
    _state: State
  ): Promise<ProviderResult> => {
    return {
      text: "I am a provider",
      values: {},
      data: {},
    };
  },
};

export class StarterService extends Service {
  static serviceType = "starter";
  capabilityDescription =
    "This is a starter service which is attached to the agent through the starter plugin.";

  constructor(runtime: IAgentRuntime) {
    super(runtime);
  }

  static async start(runtime: IAgentRuntime) {
    logger.info("*** Starting starter service ***");
    const service = new StarterService(runtime);
    return service;
  }

  static async stop(runtime: IAgentRuntime) {
    logger.info("*** Stopping starter service ***");
    // get the service from the runtime
    const service = runtime.getService(StarterService.serviceType);
    if (!service) {
      throw new Error("Starter service not found");
    }
    service.stop();
  }

  async stop() {
    logger.info("*** Stopping starter service instance ***");
  }
}

const plugin: Plugin = {
  name: "cubeai-cli",
  description:
    "Enhanced ElizaOS CLI with authentication and API integration for CUBEAI platform",
  // Set lowest priority so real models take precedence
  priority: -1000,
  config: {
    EXAMPLE_PLUGIN_VARIABLE: process.env.EXAMPLE_PLUGIN_VARIABLE,
    OWNER_API_KEYS: process.env.OWNER_API_KEYS,
    ADMIN_API_KEYS: process.env.ADMIN_API_KEYS,
    CUBEAI_API_ENDPOINT: process.env.CUBEAI_API_ENDPOINT,
    CUBEAI_INSTANCE_ID: process.env.CUBEAI_INSTANCE_ID,
  },
  async init(config: Record<string, string>, runtime: IAgentRuntime) {
    logger.info("*** Initializing CUBEAI CLI plugin ***");
    try {
      const validatedConfig = await configSchema.parseAsync(config);

      // Set all environment variables at once
      for (const [key, value] of Object.entries(validatedConfig)) {
        if (value) process.env[key] = value;
      }

      // Start the AuthService
      await AuthService.start(runtime);
      logger.info("Auth service started successfully");

      // Install global authentication middleware for all /api/* routes
      // This will run BEFORE any ElizaOS default handlers
      const app = (globalThis as any).app;
      if (app && app.use) {
        logger.info("Installing authentication middleware for /api/* routes");

        app.use("/api/*", async (req: any, res: any, next: any) => {
          try {
            // Skip authentication for public health check
            if (req.url === "/api/health" || req.url.startsWith("/health")) {
              return next();
            }

            // Extract API key from request
            const authHeader = req.headers.authorization;
            const apiKeyHeader = req.headers["x-api-key"];
            const queryApiKey = req.query.api_key;

            const apiKey =
              (authHeader && authHeader.startsWith("Bearer ")
                ? authHeader.substring(7)
                : null) ||
              (typeof apiKeyHeader === "string" ? apiKeyHeader : null) ||
              (typeof queryApiKey === "string" ? queryApiKey : null);

            if (!apiKey) {
              res.status(401).json({
                error: "Authentication required",
                message:
                  "API key must be provided via Authorization header, X-API-Key header, or api_key query parameter",
              });
              return;
            }

            // Validate API key
            const config = getAuthConfig();
            let user = null;

            if (config.ownerKeys.includes(apiKey)) {
              user = {
                id: `owner-${apiKey.slice(-8)}`,
                role: "owner",
                permissions: ["all"],
                instanceId: config.instanceId,
                apiKey,
              };
            } else if (config.adminKeys.includes(apiKey)) {
              user = {
                id: `admin-${apiKey.slice(-8)}`,
                role: "admin",
                permissions: ["read", "write"],
                instanceId: config.instanceId,
                apiKey,
              };
            }

            if (!user) {
              res.status(401).json({
                error: "Invalid API key",
                message: "The provided API key is not valid",
              });
              return;
            }

            // Add user to request for downstream handlers
            req.user = user;
            logger.info(
              `✅ Authenticated API request: ${req.method} ${req.url} from ${user.role}: ${user.id}`
            );

            // Continue to ElizaOS default handlers
            next();
          } catch (error) {
            logger.error("Authentication middleware error:", error);
            res.status(500).json({
              error: "Authentication failed",
              message: "An error occurred during authentication",
            });
          }
        });

        logger.info("✅ Authentication middleware installed successfully");
      } else {
        logger.warn(
          "⚠️ Express app not found - authentication middleware not installed"
        );
      }
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new Error(
          `Invalid plugin configuration: ${error.errors
            .map((e) => e.message)
            .join(", ")}`
        );
      }
      throw error;
    }
  },
  models: {
    [ModelType.TEXT_SMALL]: async (
      _runtime,
      { prompt, stopSequences = [] }: GenerateTextParams
    ) => {
      return "Never gonna give you up, never gonna let you down, never gonna run around and desert you...";
    },
    [ModelType.TEXT_LARGE]: async (
      _runtime,
      {
        prompt,
        stopSequences = [],
        maxTokens = 8192,
        temperature = 0.7,
        frequencyPenalty = 0.7,
        presencePenalty = 0.7,
      }: GenerateTextParams
    ) => {
      return "Never gonna make you cry, never gonna say goodbye, never gonna tell a lie and hurt you...";
    },
  },
  routes: [
    // Public health check (no auth required)
    {
      name: "health",
      path: "/health",
      type: "GET",
      handler: async (req: any, res: any, _runtime: IAgentRuntime) => {
        await Promise.resolve(healthCheck(req, res));
      },
    },
    // Auth status endpoint (requires authentication)
    {
      name: "auth-status",
      path: "/api/auth/status",
      type: "GET",
      handler: async (req: any, res: any, _runtime: IAgentRuntime) => {
        // Manual authentication check since this is a custom route
        const authHeader = req.headers.authorization;
        const apiKeyHeader = req.headers["x-api-key"];
        const queryApiKey = req.query.api_key;

        const apiKey =
          (authHeader && authHeader.startsWith("Bearer ")
            ? authHeader.substring(7)
            : null) ||
          (typeof apiKeyHeader === "string" ? apiKeyHeader : null) ||
          (typeof queryApiKey === "string" ? queryApiKey : null);

        if (!apiKey) {
          res.status(401).json({
            error: "Authentication required",
            message:
              "API key must be provided via Authorization header, X-API-Key header, or api_key query parameter",
          });
          return;
        }

        // Validate API key
        const config = getAuthConfig();
        let user = null;

        if (config.ownerKeys.includes(apiKey)) {
          user = {
            id: `owner-${apiKey.slice(-8)}`,
            role: "owner",
            permissions: ["all"],
            instanceId: config.instanceId,
            apiKey,
          };
        } else if (config.adminKeys.includes(apiKey)) {
          user = {
            id: `admin-${apiKey.slice(-8)}`,
            role: "admin",
            permissions: ["read", "write"],
            instanceId: config.instanceId,
            apiKey,
          };
        }

        if (!user) {
          res.status(401).json({
            error: "Invalid API key",
            message: "The provided API key is not valid",
          });
          return;
        }

        res.json({
          status: "authenticated",
          user: {
            id: user.id,
            role: user.role,
            permissions: user.permissions,
            instanceId: user.instanceId,
          },
          timestamp: new Date().toISOString(),
        });
      },
    },
    // Legacy hello world route (keeping for backward compatibility)
    {
      name: "helloworld",
      path: "/helloworld",
      type: "GET",
      handler: async (_req: any, res: any) => {
        res.json({
          message: "Hello World!",
        });
      },
    },
    // Agent creation endpoint
    {
      name: "create-agent",
      path: "/api/agents/create",
      type: "POST",
      handler: async (req: any, res: any, runtime: IAgentRuntime) => {
        try {
          // Validate request body
          const { characterJson } = req.body;

          if (!characterJson) {
            res.status(400).json({
              error: "Missing character data",
              message: "characterJson is required in request body",
            });
            return;
          }

          // Validate required fields
          if (!characterJson.name || !characterJson.system) {
            res.status(400).json({
              error: "Invalid character data",
              message: "name and system prompt are required",
            });
            return;
          }

          logger.info(`Creating new agent: ${characterJson.name}`);
          logger.info(
            `Agent settings: ${JSON.stringify(
              characterJson.settings || {},
              null,
              2
            )}`
          );

          // Create agent using ElizaOS runtime with default settings
          const agentData: Partial<Agent> = {
            ...characterJson,
            // Add default settings if not provided
            settings: {
              // Default ElizaOS settings
              temperature: characterJson.settings?.temperature || 0.7,
              maxTokens: characterJson.settings?.maxTokens || 2048,
              // Add default model settings
              model: "gpt-4",
              // Add default behavior settings
              enableMemory: true,
              enableActions: true,
              enableProviders: true,
              // Add default conversation settings
              conversationLength: 32,
              maxWorkingMemoryEntries: 50,
              // Add default secrets (will be injected by container manager)
              secrets: {
                OPENAI_API_KEY:
                  process.env.OPENAI_API_KEY || "{{OPENAI_API_KEY}}",
                OPENAI_BASE_URL:
                  process.env.OPENAI_BASE_URL || "https://openrouter.ai/api/v1",
                OPENAI_LARGE_MODEL:
                  process.env.OPENAI_LARGE_MODEL ||
                  "deepseek/deepseek-chat-v3-0324:free",
                OPENAI_MEDIUM_MODEL:
                  process.env.OPENAI_MEDIUM_MODEL ||
                  "deepseek/deepseek-chat-v3-0324:free",
                OPENAI_SMALL_MODEL:
                  process.env.OPENAI_SMALL_MODEL ||
                  "deepseek/deepseek-chat-v3-0324:free",
                // Fallback to Ollama if local AI is preferred
                OLLAMA_SMALL_MODEL:
                  process.env.OLLAMA_SMALL_MODEL || "gemma3:1b",
                OLLAMA_MEDIUM_MODEL:
                  process.env.OLLAMA_MEDIUM_MODEL || "gemma3:1b",
                OLLAMA_LARGE_MODEL:
                  process.env.OLLAMA_LARGE_MODEL || "gemma3:1b",
                OLLAMA_EMBEDDING_MODEL:
                  process.env.OLLAMA_EMBEDDING_MODEL || "nomic-embed-text",
                USE_LOCAL_AI: process.env.USE_LOCAL_AI || "false",
                POSTGRES_URL: process.env.POSTGRES_URL,
                OLLAMA_API_ENDPOINT: process.env.OLLAMA_API_ENDPOINT,
                // Merge any additional secrets from characterJson
                ...(characterJson.settings?.secrets || {}),
              },
              // Merge any additional settings from characterJson
              ...characterJson.settings,
            },
            // Add default plugins if not provided
            plugins: characterJson.plugins || [
              "@elizaos/plugin-sql",
              "@elizaos/plugin-bootstrap",
              "@elizaos/plugin-openai",
              "cubeai-cli",
            ],
            createdAt: Date.now(),
            updatedAt: Date.now(),
            enabled: true,
            status: AgentStatus.ACTIVE,
          };

          const success = await runtime.createAgent(agentData);

          if (!success) {
            throw new Error(`Failed to create agent: ${characterJson.name}`);
          }

          // Get the created agent to return its ID
          const agents = await runtime.getAgents();
          const createdAgent = agents.find(
            (agent) => agent.name === characterJson.name
          );

          if (!createdAgent) {
            throw new Error(
              `Agent created but not found in database: ${characterJson.name}`
            );
          }

          logger.info(
            `✅ Agent created successfully with ID: ${createdAgent.id}`
          );

          res.json({
            success: true,
            agentId: createdAgent.id,
            message: `Agent "${characterJson.name}" created successfully`,
            character: characterJson,
          });
        } catch (error) {
          logger.error("Error creating agent:", error);
          res.status(500).json({
            error: "Failed to create agent",
            message:
              error instanceof Error ? error.message : "Unknown error occurred",
          });
        }
      },
    },
  ],
  events: {
    MESSAGE_RECEIVED: [
      async (params) => {
        logger.info("MESSAGE_RECEIVED event received");
        // print the keys
        logger.info(Object.keys(params));
      },
    ],
    VOICE_MESSAGE_RECEIVED: [
      async (params) => {
        logger.info("VOICE_MESSAGE_RECEIVED event received");
        // print the keys
        logger.info(Object.keys(params));
      },
    ],
    WORLD_CONNECTED: [
      async (params) => {
        logger.info("WORLD_CONNECTED event received");
        // print the keys
        logger.info(Object.keys(params));
      },
    ],
    WORLD_JOINED: [
      async (params) => {
        logger.info("WORLD_JOINED event received");
        // print the keys
        logger.info(Object.keys(params));
      },
    ],
  },
  services: [StarterService, AuthService],
  actions: [helloWorldAction],
  providers: [helloWorldProvider],
};

export default plugin;
