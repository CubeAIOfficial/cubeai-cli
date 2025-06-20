import type { Plugin } from '@elizaos/core';
import {
  type Action,
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
} from '@elizaos/core';
import { z } from 'zod';
import {
  getAuthConfig,
  healthCheck
} from './middleware/auth.js';
import { AuthService } from './services/auth-service.js';

/**
 * Define the configuration schema for the plugin with the following properties:
 *
 * @param {string} EXAMPLE_PLUGIN_VARIABLE - The name of the plugin (min length of 1, optional)
 * @returns {object} - The configured schema object
 */
const configSchema = z.object({
  EXAMPLE_PLUGIN_VARIABLE: z
    .string()
    .min(1, 'Example plugin variable is not provided')
    .optional()
    .transform((val) => {
      if (!val) {
        console.warn('Warning: Example plugin variable is not provided');
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
  name: 'HELLO_WORLD',
  similes: ['GREET', 'SAY_HELLO'],
  description: 'Responds with a simple hello world message',

  validate: async (_runtime: IAgentRuntime, _message: Memory, _state: State): Promise<boolean> => {
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
      logger.info('Handling HELLO_WORLD action');

      // Simple response content
      const responseContent: Content = {
        text: 'hello world!',
        actions: ['HELLO_WORLD'],
        source: message.content.source,
      };

      // Call back with the hello world message
      await callback(responseContent);

      return responseContent;
    } catch (error) {
      logger.error('Error in HELLO_WORLD action:', error);
      throw error;
    }
  },

  examples: [
    [
      {
        name: '{{name1}}',
        content: {
          text: 'Can you say hello?',
        },
      },
      {
        name: '{{name2}}',
        content: {
          text: 'hello world!',
          actions: ['HELLO_WORLD'],
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
  name: 'HELLO_WORLD_PROVIDER',
  description: 'A simple example provider',

  get: async (
    _runtime: IAgentRuntime,
    _message: Memory,
    _state: State
  ): Promise<ProviderResult> => {
    return {
      text: 'I am a provider',
      values: {},
      data: {},
    };
  },
};

export class StarterService extends Service {
  static serviceType = 'starter';
  capabilityDescription =
    'This is a starter service which is attached to the agent through the starter plugin.';

  constructor(runtime: IAgentRuntime) {
    super(runtime);
  }

  static async start(runtime: IAgentRuntime) {
    logger.info('*** Starting starter service ***');
    const service = new StarterService(runtime);
    return service;
  }

  static async stop(runtime: IAgentRuntime) {
    logger.info('*** Stopping starter service ***');
    // get the service from the runtime
    const service = runtime.getService(StarterService.serviceType);
    if (!service) {
      throw new Error('Starter service not found');
    }
    service.stop();
  }

  async stop() {
    logger.info('*** Stopping starter service instance ***');
  }
}

const plugin: Plugin = {
  name: 'cubeai-cli',
  description: 'Enhanced ElizaOS CLI with authentication and API integration for CUBEAI platform',
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
    logger.info('*** Initializing CUBEAI CLI plugin ***');
    try {
      const validatedConfig = await configSchema.parseAsync(config);

      // Set all environment variables at once
      for (const [key, value] of Object.entries(validatedConfig)) {
        if (value) process.env[key] = value;
      }

      // Start the AuthService
      await AuthService.start(runtime);
      logger.info('Auth service started successfully');
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new Error(
          `Invalid plugin configuration: ${error.errors.map((e) => e.message).join(', ')}`
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
      return 'Never gonna give you up, never gonna let you down, never gonna run around and desert you...';
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
      return 'Never gonna make you cry, never gonna say goodbye, never gonna tell a lie and hurt you...';
    },
  },
  routes: [
    // Public health check
    {
      name: 'health',
      path: '/health',
      type: 'GET',
      handler: async (req: any, res: any, _runtime: IAgentRuntime) => {
        await Promise.resolve(healthCheck(req, res));
      },
    },
    // Legacy hello world route (keeping for backward compatibility)
    {
      name: 'helloworld',
      path: '/helloworld',
      type: 'GET',
      handler: async (_req: any, res: any) => {
        res.json({
          message: 'Hello World!',
        });
      },
    },
    // Authentication status - requires valid API key
    {
      name: 'auth-status',
      path: '/api/auth/status',
      type: 'GET',
      handler: async (req: any, res: any, runtime: IAgentRuntime) => {
        try {
          // Extract API key from request
          const authHeader = req.headers.authorization;
          const apiKeyHeader = req.headers['x-api-key'];
          const queryApiKey = req.query.api_key;

          const apiKey = (authHeader && authHeader.startsWith('Bearer ') ? authHeader.substring(7) : null) ||
            (typeof apiKeyHeader === 'string' ? apiKeyHeader : null) ||
            (typeof queryApiKey === 'string' ? queryApiKey : null);

          if (!apiKey) {
            res.status(401).json({
              error: 'Authentication required',
              message: 'API key must be provided via Authorization header, X-API-Key header, or api_key query parameter'
            });
            return;
          }

          // Validate API key
          const config = getAuthConfig();
          let user = null;

          if (config.ownerKeys.includes(apiKey)) {
            user = {
              id: `owner-${apiKey.slice(-8)}`,
              role: 'owner',
              permissions: ['all'],
              instanceId: config.instanceId,
              apiKey
            };
          } else if (config.adminKeys.includes(apiKey)) {
            user = {
              id: `admin-${apiKey.slice(-8)}`,
              role: 'admin',
              permissions: ['read', 'write'],
              instanceId: config.instanceId,
              apiKey
            };
          }

          if (!user) {
            res.status(401).json({
              error: 'Invalid API key',
              message: 'The provided API key is not valid'
            });
            return;
          }

          res.json({
            authenticated: true,
            user: {
              id: user.id,
              role: user.role,
              permissions: user.permissions,
              instanceId: user.instanceId
            }
          });
        } catch (error) {
          logger.error('Auth status error:', error);
          res.status(500).json({
            error: 'Authentication failed',
            message: 'An error occurred during authentication'
          });
        }
      },
    },
    // Get current user info - requires valid API key
    {
      name: 'auth-me',
      path: '/api/auth/me',
      type: 'GET',
      handler: async (req: any, res: any, runtime: IAgentRuntime) => {
        try {
          // Extract and validate API key
          const authHeader = req.headers.authorization;
          const apiKeyHeader = req.headers['x-api-key'];
          const queryApiKey = req.query.api_key;

          const apiKey = (authHeader && authHeader.startsWith('Bearer ') ? authHeader.substring(7) : null) ||
            (typeof apiKeyHeader === 'string' ? apiKeyHeader : null) ||
            (typeof queryApiKey === 'string' ? queryApiKey : null);

          if (!apiKey) {
            res.status(401).json({
              error: 'Authentication required',
              message: 'API key must be provided'
            });
            return;
          }

          const config = getAuthConfig();
          let user = null;

          if (config.ownerKeys.includes(apiKey)) {
            user = {
              id: `owner-${apiKey.slice(-8)}`,
              role: 'owner',
              permissions: ['all'],
              instanceId: config.instanceId
            };
          } else if (config.adminKeys.includes(apiKey)) {
            user = {
              id: `admin-${apiKey.slice(-8)}`,
              role: 'admin',
              permissions: ['read', 'write'],
              instanceId: config.instanceId
            };
          }

          if (!user) {
            res.status(401).json({
              error: 'Invalid API key'
            });
            return;
          }

          const authService = runtime.getService('auth') as AuthService;
          const sessions = authService?.getUserSessions(user.id) || [];

          res.json({
            user,
            sessions: sessions.length,
            lastActivity: sessions[0]?.lastActivity || new Date(),
            instanceId: user.instanceId
          });
        } catch (error) {
          logger.error('Auth me error:', error);
          res.status(500).json({
            error: 'Authentication failed'
          });
        }
      },
    },
    // List agents - requires valid API key and read permissions
    {
      name: 'agents-list',
      path: '/api/agents',
      type: 'GET',
      handler: async (req: any, res: any, runtime: IAgentRuntime) => {
        try {
          // Extract and validate API key
          const authHeader = req.headers.authorization;
          const apiKeyHeader = req.headers['x-api-key'];
          const queryApiKey = req.query.api_key;

          const apiKey = (authHeader && authHeader.startsWith('Bearer ') ? authHeader.substring(7) : null) ||
            (typeof apiKeyHeader === 'string' ? apiKeyHeader : null) ||
            (typeof queryApiKey === 'string' ? queryApiKey : null);

          if (!apiKey) {
            res.status(401).json({
              error: 'Authentication required',
              message: 'API key must be provided to access agents'
            });
            return;
          }

          const config = getAuthConfig();
          let user = null;

          if (config.ownerKeys.includes(apiKey)) {
            user = {
              id: `owner-${apiKey.slice(-8)}`,
              role: 'owner',
              permissions: ['all'],
              instanceId: config.instanceId
            };
          } else if (config.adminKeys.includes(apiKey)) {
            user = {
              id: `admin-${apiKey.slice(-8)}`,
              role: 'admin',
              permissions: ['read', 'write'],
              instanceId: config.instanceId
            };
          }

          if (!user) {
            res.status(401).json({
              error: 'Invalid API key',
              message: 'The provided API key is not valid'
            });
            return;
          }

          logger.info(`Authenticated agents request from ${user.role}: ${user.id}`);

          const authService = runtime.getService('auth') as AuthService;
          const userAgentAccess = authService?.getUserAgentAccess(user.id) || [];

          // For now, return basic info - you can integrate with actual agent storage later
          res.json({
            message: 'Agents endpoint - authentication successful',
            authenticated: true,
            user: {
              id: user.id,
              role: user.role,
              instanceId: user.instanceId
            },
            agents: [],
            total: 0,
            userAccess: userAgentAccess.length,
            timestamp: new Date().toISOString()
          });
        } catch (error) {
          logger.error('Agents list error:', error);
          res.status(500).json({
            error: 'Failed to retrieve agents',
            message: 'An error occurred while fetching agents'
          });
        }
      },
    },
    // Grant agent access - requires owner role
    {
      name: 'grant-agent-access',
      path: '/api/auth/agent-access',
      type: 'POST',
      handler: async (req: any, res: any, runtime: IAgentRuntime) => {
        try {
          // Extract and validate API key
          const authHeader = req.headers.authorization;
          const apiKeyHeader = req.headers['x-api-key'];

          const apiKey = (authHeader && authHeader.startsWith('Bearer ') ? authHeader.substring(7) : null) ||
            (typeof apiKeyHeader === 'string' ? apiKeyHeader : null);

          if (!apiKey) {
            res.status(401).json({
              error: 'Authentication required'
            });
            return;
          }

          const config = getAuthConfig();

          // Only owner can grant access
          if (!config.ownerKeys.includes(apiKey)) {
            res.status(403).json({
              error: 'Insufficient permissions',
              message: 'Only owners can grant agent access'
            });
            return;
          }

          const user = {
            id: `owner-${apiKey.slice(-8)}`,
            role: 'owner',
            instanceId: config.instanceId
          };

          const authService = runtime.getService('auth') as AuthService;

          if (!authService) {
            res.status(503).json({ error: 'Auth service not available' });
            return;
          }

          const { userId, agentId, permissions, expiresAt } = req.body;

          if (!userId || !agentId) {
            res.status(400).json({
              error: 'Missing required fields',
              message: 'userId and agentId are required'
            });
            return;
          }

          await authService.grantAgentAccess(
            userId,
            agentId,
            permissions || [],
            expiresAt ? new Date(expiresAt) : undefined
          );

          res.json({
            success: true,
            message: 'Agent access granted',
            userId,
            agentId,
            permissions: permissions || [],
            grantedBy: user.id
          });
        } catch (error) {
          logger.error('Failed to grant agent access:', error);
          res.status(500).json({ error: 'Failed to grant access' });
        }
      },
    },
  ],
  events: {
    MESSAGE_RECEIVED: [
      async (params) => {
        logger.info('MESSAGE_RECEIVED event received');
        // print the keys
        logger.info(Object.keys(params));
      },
    ],
    VOICE_MESSAGE_RECEIVED: [
      async (params) => {
        logger.info('VOICE_MESSAGE_RECEIVED event received');
        // print the keys
        logger.info(Object.keys(params));
      },
    ],
    WORLD_CONNECTED: [
      async (params) => {
        logger.info('WORLD_CONNECTED event received');
        // print the keys
        logger.info(Object.keys(params));
      },
    ],
    WORLD_JOINED: [
      async (params) => {
        logger.info('WORLD_JOINED event received');
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
