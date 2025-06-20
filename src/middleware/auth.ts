import { logger } from '@elizaos/core';
import { NextFunction, Request, Response } from 'express';
import { z } from 'zod';

// Define user roles and permissions
export enum UserRole {
    OWNER = 'owner',
    ADMIN = 'admin',
    USER = 'user',
    GUEST = 'guest'
}

export enum Permission {
    // Agent management
    AGENTS_READ = 'agents:read',
    AGENTS_WRITE = 'agents:write',
    AGENTS_DELETE = 'agents:delete',

    // Conversation management
    CONVERSATIONS_READ = 'conversations:read',
    CONVERSATIONS_WRITE = 'conversations:write',
    CONVERSATIONS_DELETE = 'conversations:delete',

    // System management
    SYSTEM_READ = 'system:read',
    SYSTEM_WRITE = 'system:write',
    SYSTEM_ADMIN = 'system:admin',

    // Memory management
    MEMORY_READ = 'memory:read',
    MEMORY_WRITE = 'memory:write',
    MEMORY_DELETE = 'memory:delete'
}

// Role-based permissions mapping
const ROLE_PERMISSIONS: Record<UserRole, Permission[]> = {
    [UserRole.OWNER]: [
        Permission.AGENTS_READ,
        Permission.AGENTS_WRITE,
        Permission.AGENTS_DELETE,
        Permission.CONVERSATIONS_READ,
        Permission.CONVERSATIONS_WRITE,
        Permission.CONVERSATIONS_DELETE,
        Permission.SYSTEM_READ,
        Permission.SYSTEM_WRITE,
        Permission.SYSTEM_ADMIN,
        Permission.MEMORY_READ,
        Permission.MEMORY_WRITE,
        Permission.MEMORY_DELETE
    ],
    [UserRole.ADMIN]: [
        Permission.AGENTS_READ,
        Permission.AGENTS_WRITE,
        Permission.CONVERSATIONS_READ,
        Permission.CONVERSATIONS_WRITE,
        Permission.SYSTEM_READ,
        Permission.MEMORY_READ,
        Permission.MEMORY_WRITE
    ],
    [UserRole.USER]: [
        Permission.AGENTS_READ,
        Permission.CONVERSATIONS_READ,
        Permission.CONVERSATIONS_WRITE,
        Permission.MEMORY_READ
    ],
    [UserRole.GUEST]: [
        Permission.AGENTS_READ,
        Permission.CONVERSATIONS_READ
    ]
};

// User interface for authenticated requests
export interface AuthenticatedUser {
    id: string;
    email?: string;
    role: UserRole;
    permissions: Permission[];
    instanceId: string; // CUBEAI instance this user belongs to
    apiKey?: string;
    metadata?: Record<string, any>;
}

// Extended Request interface with user info
export interface AuthenticatedRequest extends Request {
    user?: AuthenticatedUser;
}

// API Key configuration schema
const apiKeyConfigSchema = z.object({
    OWNER_API_KEYS: z.string().optional(),
    ADMIN_API_KEYS: z.string().optional(),
    CUBEAI_API_ENDPOINT: z.string().url().optional(),
    CUBEAI_INSTANCE_ID: z.string().optional(),
});

// Parse and validate API keys from environment
const parseApiKeys = (keys: string = ''): string[] => {
    return keys.split(',').map(key => key.trim()).filter(key => key.length > 0);
};

// Get API key configuration
export const getAuthConfig = () => {
    try {
        const config = apiKeyConfigSchema.parse({
            OWNER_API_KEYS: process.env.OWNER_API_KEYS,
            ADMIN_API_KEYS: process.env.ADMIN_API_KEYS,
            CUBEAI_API_ENDPOINT: process.env.CUBEAI_API_ENDPOINT,
            CUBEAI_INSTANCE_ID: process.env.CUBEAI_INSTANCE_ID,
        });

        return {
            ownerKeys: parseApiKeys(config.OWNER_API_KEYS),
            adminKeys: parseApiKeys(config.ADMIN_API_KEYS),
            cubeaiEndpoint: config.CUBEAI_API_ENDPOINT,
            instanceId: config.CUBEAI_INSTANCE_ID || 'default'
        };
    } catch (error) {
        logger.error('Invalid auth configuration:', error);
        return {
            ownerKeys: [],
            adminKeys: [],
            cubeaiEndpoint: undefined,
            instanceId: 'default'
        };
    }
};

// Validate API key and determine user role
const validateApiKey = async (apiKey: string): Promise<AuthenticatedUser | null> => {
    const config = getAuthConfig();

    // Check owner keys
    if (config.ownerKeys.includes(apiKey)) {
        return {
            id: `owner-${apiKey.slice(-8)}`,
            role: UserRole.OWNER,
            permissions: ROLE_PERMISSIONS[UserRole.OWNER],
            instanceId: config.instanceId,
            apiKey
        };
    }

    // Check admin keys
    if (config.adminKeys.includes(apiKey)) {
        return {
            id: `admin-${apiKey.slice(-8)}`,
            role: UserRole.ADMIN,
            permissions: ROLE_PERMISSIONS[UserRole.ADMIN],
            instanceId: config.instanceId,
            apiKey
        };
    }

    // If CUBEAI endpoint is configured, validate with platform
    if (config.cubeaiEndpoint) {
        try {
            const user = await validateWithCubeaiPlatform(apiKey, config.cubeaiEndpoint, config.instanceId);
            if (user) return user;
        } catch (error) {
            logger.error('Error validating with CUBEAI platform:', error);
        }
    }

    return null;
};

// Validate with CUBEAI platform API
const validateWithCubeaiPlatform = async (
    apiKey: string,
    endpoint: string,
    instanceId: string
): Promise<AuthenticatedUser | null> => {
    try {
        const response = await fetch(`${endpoint}/api/auth/validate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            },
            body: JSON.stringify({ instanceId })
        });

        if (!response.ok) {
            return null;
        }

        const data = await response.json();

        return {
            id: data.user.id,
            email: data.user.email,
            role: data.user.role || UserRole.USER,
            permissions: ROLE_PERMISSIONS[data.user.role || UserRole.USER],
            instanceId,
            apiKey,
            metadata: data.user.metadata
        };
    } catch (error) {
        logger.error('Platform validation failed:', error);
        return null;
    }
};

// Extract API key from request
const extractApiKey = (req: Request): string | null => {
    // Check Authorization header
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        return authHeader.substring(7);
    }

    // Check X-API-Key header
    const apiKeyHeader = req.headers['x-api-key'];
    if (apiKeyHeader && typeof apiKeyHeader === 'string') {
        return apiKeyHeader;
    }

    // Check query parameter
    const queryApiKey = req.query.api_key;
    if (queryApiKey && typeof queryApiKey === 'string') {
        return queryApiKey;
    }

    return null;
};

// Main authentication middleware
export const authenticate = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
): Promise<void> => {
    try {
        const apiKey = extractApiKey(req);

        if (!apiKey) {
            res.status(401).json({
                error: 'Authentication required',
                message: 'API key must be provided via Authorization header, X-API-Key header, or api_key query parameter'
            });
            return;
        }

        const user = await validateApiKey(apiKey);

        if (!user) {
            res.status(401).json({
                error: 'Invalid API key',
                message: 'The provided API key is not valid or has expired'
            });
            return;
        }

        // Attach user to request
        req.user = user;

        logger.info(`Authenticated user: ${user.id} (${user.role}) for instance: ${user.instanceId}`);
        next();
    } catch (error) {
        logger.error('Authentication error:', error);
        res.status(500).json({
            error: 'Authentication failed',
            message: 'An error occurred during authentication'
        });
    }
};

// Authorization middleware - check if user has required permission
export const authorize = (requiredPermission: Permission) => {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
        if (!req.user) {
            res.status(401).json({
                error: 'Authentication required',
                message: 'User must be authenticated to access this resource'
            });
            return;
        }

        if (!req.user.permissions.includes(requiredPermission)) {
            res.status(403).json({
                error: 'Insufficient permissions',
                message: `Required permission: ${requiredPermission}`,
                userRole: req.user.role,
                userPermissions: req.user.permissions
            });
            return;
        }

        next();
    };
};

// Multiple permissions authorization (user needs ALL permissions)
export const authorizeAll = (requiredPermissions: Permission[]) => {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
        if (!req.user) {
            res.status(401).json({
                error: 'Authentication required'
            });
            return;
        }

        const missingPermissions = requiredPermissions.filter(
            permission => !req.user!.permissions.includes(permission)
        );

        if (missingPermissions.length > 0) {
            res.status(403).json({
                error: 'Insufficient permissions',
                message: `Missing permissions: ${missingPermissions.join(', ')}`,
                userRole: req.user.role
            });
            return;
        }

        next();
    };
};

// Alternative permissions authorization (user needs ANY of the permissions)
export const authorizeAny = (requiredPermissions: Permission[]) => {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
        if (!req.user) {
            res.status(401).json({
                error: 'Authentication required'
            });
            return;
        }

        const hasPermission = requiredPermissions.some(
            permission => req.user!.permissions.includes(permission)
        );

        if (!hasPermission) {
            res.status(403).json({
                error: 'Insufficient permissions',
                message: `Required one of: ${requiredPermissions.join(', ')}`,
                userRole: req.user.role
            });
            return;
        }

        next();
    };
};

// Role-based authorization
export const authorizeRole = (requiredRole: UserRole) => {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
        if (!req.user) {
            res.status(401).json({
                error: 'Authentication required'
            });
            return;
        }

        if (req.user.role !== requiredRole) {
            res.status(403).json({
                error: 'Insufficient role',
                message: `Required role: ${requiredRole}`,
                userRole: req.user.role
            });
            return;
        }

        next();
    };
};

// Instance isolation middleware - ensure user can only access their instance data
export const enforceInstanceIsolation = (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
        res.status(401).json({
            error: 'Authentication required'
        });
        return;
    }

    // Add instance filter to request for database queries
    if (!req.params) req.params = {};
    req.params.instanceId = req.user.instanceId;

    next();
};

// Utility function to check if user has permission
export const hasPermission = (user: AuthenticatedUser, permission: Permission): boolean => {
    return user.permissions.includes(permission);
};

// Utility function to check if user has role
export const hasRole = (user: AuthenticatedUser, role: UserRole): boolean => {
    return user.role === role;
};

// Health check endpoint (no auth required)
export const healthCheck = (req: Request, res: Response): void => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        instance: getAuthConfig().instanceId
    });
}; 