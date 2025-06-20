import { logger } from '@elizaos/core';
import { Socket } from 'socket.io';
import { AuthService } from '../services/auth-service.js';
import { AuthenticatedUser } from './auth.js';

export interface AuthenticatedSocket extends Socket {
    user?: AuthenticatedUser;
    sessionId?: string;
}

// WebSocket authentication middleware
export const authenticateSocket = (authService: AuthService) => {
    return async (socket: AuthenticatedSocket, next: (err?: Error) => void) => {
        try {
            // Extract token from auth header or query
            const token = socket.handshake.auth?.token ||
                socket.handshake.query?.token ||
                socket.handshake.headers?.authorization?.replace('Bearer ', '');

            if (!token) {
                logger.warn(`WebSocket connection rejected: No token provided (${socket.id})`);
                return next(new Error('Authentication token required'));
            }

            // Validate token using auth service
            const user = await authService.validateWebSocketConnection(token as string);

            if (!user) {
                logger.warn(`WebSocket connection rejected: Invalid token (${socket.id})`);
                return next(new Error('Invalid authentication token'));
            }

            // Create session for this WebSocket connection
            const session = await authService.createSession(user);

            // Attach user and session to socket
            socket.user = user;
            socket.sessionId = session.id;

            logger.info(`WebSocket authenticated: ${user.id} (${user.role}) - Session: ${session.id}`);
            next();
        } catch (error) {
            logger.error('WebSocket authentication error:', error);
            next(new Error('Authentication failed'));
        }
    };
};

// WebSocket authorization for specific events
export const authorizeSocketEvent = (
    requiredPermissions: string[],
    authService: AuthService
) => {
    return (socket: AuthenticatedSocket, eventData: any, next: (err?: Error) => void) => {
        if (!socket.user) {
            return next(new Error('Authentication required'));
        }

        const hasRequiredPermission = requiredPermissions.some(permission =>
            socket.user!.permissions.includes(permission as any)
        );

        if (!hasRequiredPermission) {
            logger.warn(`WebSocket event denied: User ${socket.user.id} lacks permissions ${requiredPermissions.join(', ')}`);
            return next(new Error('Insufficient permissions for this action'));
        }

        next();
    };
};

// Disconnect handler for cleaning up sessions
export const setupSocketCleanup = (authService: AuthService) => {
    return (socket: AuthenticatedSocket) => {
        socket.on('disconnect', async (reason) => {
            if (socket.sessionId) {
                await authService.updateSessionActivity(socket.sessionId);
                logger.info(`WebSocket disconnected: ${socket.user?.id} (${reason})`);
            }
        });
    };
}; 