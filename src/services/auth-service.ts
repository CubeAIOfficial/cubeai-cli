import { Service, logger, type IAgentRuntime } from '@elizaos/core';
import { AuthenticatedUser, Permission, UserRole } from '../middleware/auth.js';

export interface UserSession {
    id: string;
    userId: string;
    instanceId: string;
    startTime: Date;
    lastActivity: Date;
    isActive: boolean;
    metadata?: Record<string, any>;
}

export interface AgentAccess {
    userId: string;
    agentId: string;
    permissions: Permission[];
    grantedAt: Date;
    expiresAt?: Date;
}

export class AuthService extends Service {
    static serviceType = 'auth';

    private activeSessions = new Map<string, UserSession>();
    private agentAccess = new Map<string, AgentAccess[]>(); // userId -> AgentAccess[]
    private userCache = new Map<string, AuthenticatedUser>();

    constructor(runtime: IAgentRuntime) {
        super(runtime);
    }

    static async start(runtime: IAgentRuntime): Promise<AuthService> {
        logger.info('*** Starting Auth Service ***');

        const existingService = runtime.getService(AuthService.serviceType) as AuthService;
        if (existingService) {
            throw new Error('Auth service is already running');
        }

        const service = new AuthService(runtime);
        await service.initialize();

        runtime.registerService(AuthService.serviceType, service);
        return service;
    }

    static async stop(runtime: IAgentRuntime): Promise<void> {
        logger.info('*** Stopping Auth Service ***');
        const service = runtime.getService(AuthService.serviceType) as AuthService;
        if (!service) {
            throw new Error('Auth service not found');
        }
        await service.cleanup();
    }

    private async initialize(): Promise<void> {
        logger.info('Initializing Auth Service');

        // Load persistent sessions and access data from database if available
        await this.loadPersistedData();

        // Start session cleanup interval
        this.startSessionCleanup();
    }

    private async cleanup(): Promise<void> {
        logger.info('Cleaning up Auth Service');

        // Save active sessions and access data
        await this.persistData();

        // Clear in-memory data
        this.activeSessions.clear();
        this.agentAccess.clear();
        this.userCache.clear();
    }

    private async loadPersistedData(): Promise<void> {
        try {
            // Load from database if available
            const sessionsData = await this.runtime.db.get('auth:sessions');
            if (sessionsData) {
                const sessions = JSON.parse(sessionsData);
                for (const session of sessions) {
                    this.activeSessions.set(session.id, {
                        ...session,
                        startTime: new Date(session.startTime),
                        lastActivity: new Date(session.lastActivity)
                    });
                }
            }

            const accessData = await this.runtime.db.get('auth:agent_access');
            if (accessData) {
                const accessMap = JSON.parse(accessData);
                for (const [userId, accesses] of Object.entries(accessMap)) {
                    this.agentAccess.set(userId, (accesses as any[]).map(access => ({
                        ...access,
                        grantedAt: new Date(access.grantedAt),
                        expiresAt: access.expiresAt ? new Date(access.expiresAt) : undefined
                    })));
                }
            }
        } catch (error) {
            logger.error('Failed to load persisted auth data:', error);
        }
    }

    private async persistData(): Promise<void> {
        try {
            // Convert sessions to serializable format
            const sessions = Array.from(this.activeSessions.values());
            await this.runtime.db.set('auth:sessions', JSON.stringify(sessions));

            // Convert agent access to serializable format
            const accessMap = Object.fromEntries(this.agentAccess.entries());
            await this.runtime.db.set('auth:agent_access', JSON.stringify(accessMap));
        } catch (error) {
            logger.error('Failed to persist auth data:', error);
        }
    }

    private startSessionCleanup(): void {
        // Clean up expired sessions every 5 minutes
        setInterval(() => {
            this.cleanupExpiredSessions();
        }, 5 * 60 * 1000);
    }

    private cleanupExpiredSessions(): void {
        const now = new Date();
        const sessionTimeout = 24 * 60 * 60 * 1000; // 24 hours

        for (const [sessionId, session] of this.activeSessions.entries()) {
            const timeSinceActivity = now.getTime() - session.lastActivity.getTime();

            if (timeSinceActivity > sessionTimeout) {
                this.activeSessions.delete(sessionId);
                logger.info(`Cleaned up expired session: ${sessionId}`);
            }
        }
    }

    // Create a new user session
    async createSession(user: AuthenticatedUser): Promise<UserSession> {
        const sessionId = `session-${user.id}-${Date.now()}`;
        const now = new Date();

        const session: UserSession = {
            id: sessionId,
            userId: user.id,
            instanceId: user.instanceId,
            startTime: now,
            lastActivity: now,
            isActive: true,
            metadata: { role: user.role, permissions: user.permissions }
        };

        this.activeSessions.set(sessionId, session);
        this.userCache.set(user.id, user);

        logger.info(`Created session ${sessionId} for user ${user.id}`);
        return session;
    }

    // Update session activity
    async updateSessionActivity(sessionId: string): Promise<void> {
        const session = this.activeSessions.get(sessionId);
        if (session) {
            session.lastActivity = new Date();
        }
    }

    // End a user session
    async endSession(sessionId: string): Promise<void> {
        const session = this.activeSessions.get(sessionId);
        if (session) {
            session.isActive = false;
            this.activeSessions.delete(sessionId);
            logger.info(`Ended session: ${sessionId}`);
        }
    }

    // Get active session
    getSession(sessionId: string): UserSession | undefined {
        return this.activeSessions.get(sessionId);
    }

    // Get all active sessions for a user
    getUserSessions(userId: string): UserSession[] {
        return Array.from(this.activeSessions.values())
            .filter(session => session.userId === userId && session.isActive);
    }

    // Grant agent access to a user
    async grantAgentAccess(
        userId: string,
        agentId: string,
        permissions: Permission[],
        expiresAt?: Date
    ): Promise<void> {
        const access: AgentAccess = {
            userId,
            agentId,
            permissions,
            grantedAt: new Date(),
            expiresAt
        };

        const userAccess = this.agentAccess.get(userId) || [];

        // Remove existing access for this agent
        const filteredAccess = userAccess.filter(a => a.agentId !== agentId);
        filteredAccess.push(access);

        this.agentAccess.set(userId, filteredAccess);

        logger.info(`Granted agent access: ${userId} -> ${agentId}`);
    }

    // Revoke agent access from a user
    async revokeAgentAccess(userId: string, agentId: string): Promise<void> {
        const userAccess = this.agentAccess.get(userId);
        if (userAccess) {
            const filteredAccess = userAccess.filter(a => a.agentId !== agentId);
            this.agentAccess.set(userId, filteredAccess);
            logger.info(`Revoked agent access: ${userId} -> ${agentId}`);
        }
    }

    // Check if user has access to agent
    hasAgentAccess(userId: string, agentId: string, permission?: Permission): boolean {
        const userAccess = this.agentAccess.get(userId) || [];
        const agentAccess = userAccess.find(a => a.agentId === agentId);

        if (!agentAccess) return false;

        // Check if access has expired
        if (agentAccess.expiresAt && agentAccess.expiresAt < new Date()) {
            return false;
        }

        // Check specific permission if provided
        if (permission) {
            return agentAccess.permissions.includes(permission);
        }

        return true;
    }

    // Get user's agent access permissions
    getAgentPermissions(userId: string, agentId: string): Permission[] {
        const userAccess = this.agentAccess.get(userId) || [];
        const agentAccess = userAccess.find(a => a.agentId === agentId);

        if (!agentAccess || (agentAccess.expiresAt && agentAccess.expiresAt < new Date())) {
            return [];
        }

        return agentAccess.permissions;
    }

    // Get all agents user has access to
    getUserAgentAccess(userId: string): AgentAccess[] {
        const userAccess = this.agentAccess.get(userId) || [];
        const now = new Date();

        return userAccess.filter(access =>
            !access.expiresAt || access.expiresAt > now
        );
    }

    // Validate WebSocket connection
    async validateWebSocketConnection(token: string): Promise<AuthenticatedUser | null> {
        try {
            // Token could be API key or session ID
            const cachedUser = Array.from(this.userCache.values())
                .find(user => user.apiKey === token);

            if (cachedUser) {
                return cachedUser;
            }

            // If not in cache, validate as API key
            // This would use the same validation logic as the HTTP middleware
            return null;
        } catch (error) {
            logger.error('WebSocket validation error:', error);
            return null;
        }
    }

    // Get authentication statistics
    getAuthStats(): {
        activeSessions: number;
        totalUsers: number;
        usersByRole: Record<UserRole, number>;
        agentAccessGrants: number;
    } {
        const activeSessions = this.activeSessions.size;
        const users = Array.from(this.userCache.values());
        const totalUsers = users.length;

        const usersByRole = users.reduce((acc, user) => {
            acc[user.role] = (acc[user.role] || 0) + 1;
            return acc;
        }, {} as Record<UserRole, number>);

        const agentAccessGrants = Array.from(this.agentAccess.values())
            .reduce((total, accesses) => total + accesses.length, 0);

        return {
            activeSessions,
            totalUsers,
            usersByRole,
            agentAccessGrants
        };
    }
} 