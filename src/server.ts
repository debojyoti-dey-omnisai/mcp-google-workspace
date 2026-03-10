#!/usr/bin/env node

import * as dotenv from "dotenv";
import { parseArgs } from "node:util";
import { randomUUID } from "node:crypto";
import { createServer, IncomingMessage, ServerResponse } from "http";
import { parse as parseUrl } from "url";
import { parse as parseQueryString } from "querystring";
// open is no longer used — auth URL is returned to the client instead

// Load environment variables from .env file as fallback
dotenv.config();

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  isInitializeRequest,
} from "@modelcontextprotocol/sdk/types.js";
import { GmailTools } from "./tools/gmail.js";
import { CalendarTools } from "./tools/calendar.js";
import { GAuthService } from "./services/gauth.js";

// Configure logging
const logger = {
  info: (msg: string) => console.error(`[INFO] ${msg}`),
  error: (msg: string, error?: Error) => {
    console.error(`[ERROR] ${msg}`);
    if (error?.stack) console.error(error.stack);
  },
};

interface ServerConfig {
  gauthFile: string;
  accountsFile: string;
  credentialsDir: string;
}

class OAuthServer {
  private server: ReturnType<typeof createServer>;
  private gauth: GAuthService;

  constructor(gauth: GAuthService) {
    this.gauth = gauth;
    this.server = createServer(this.handleRequest.bind(this));
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse) {
    const url = parseUrl(req.url || "");
    if (url.pathname !== "/code") {
      res.writeHead(404);
      res.end();
      return;
    }

    const query = parseQueryString(url.query || "");
    if (!query.code) {
      res.writeHead(400);
      res.end();
      return;
    }

    res.writeHead(200);
    res.write("Auth successful! You can close the tab!");
    res.end();

    const storage = {};
    await this.gauth.getCredentials(query.code as string, storage);
    this.server.close();
  }

  listen(port: number = 4100) {
    this.server.listen(port);
  }
}

class GoogleWorkspaceServer {
  private server: Server;
  private gauth: GAuthService;
  private tools!: {
    gmail: GmailTools;
    calendar: CalendarTools;
  };

  constructor(config: ServerConfig) {
    logger.info("Starting Google Workspace MCP Server...");

    // Initialize services
    this.gauth = new GAuthService(config);

    // Initialize server
    this.server = new Server(
      { name: "mcp-google-workspace", version: "1.0.0" },
      { capabilities: { tools: {} } },
    );
  }

  private async initializeTools() {
    // Initialize tools after OAuth2 client is ready
    this.tools = {
      gmail: new GmailTools(this.gauth),
      calendar: new CalendarTools(this.gauth),
    };

    this.setupHandlers();
  }

  /**
   * Returns the auth URL if credentials are missing or expired, or null if auth is ready.
   */
  private async setupOAuth2(userId: string): Promise<string | null> {
    const accounts = await this.gauth.getAccountInfo();
    if (accounts.length === 0) {
      throw new Error("No accounts specified in .gauth.json");
    }
    if (!accounts.some((a) => a.email === userId)) {
      throw new Error(
        `Account for email: ${userId} not specified in .gauth.json`,
      );
    }

    let credentials = await this.gauth.getStoredCredentials(userId);
    if (!credentials) {
      const authUrl = await this.gauth.getAuthorizationUrl(userId, {});
      // Start the OAuth callback server so the redirect works
      const oauthServer = new OAuthServer(this.gauth);
      oauthServer.listen(4100);
      return authUrl;
    }

    const tokens = credentials.credentials;
    if (tokens.expiry_date && tokens.expiry_date < Date.now()) {
      logger.info("Access token expired, refreshing...");
      try {
        const { credentials: newTokens } = await credentials.refreshAccessToken();
        credentials.setCredentials(newTokens);
        await this.gauth.storeCredentials(credentials, userId);
      } catch (error) {
        logger.error("Token refresh failed, re-authentication required");
        const authUrl = await this.gauth.getAuthorizationUrl(userId, {});
        const oauthServer = new OAuthServer(this.gauth);
        oauthServer.listen(4100);
        return authUrl;
      }
    }

    // Verify credentials still work
    try {
      await this.gauth.getUserInfo(credentials);
      await this.gauth.storeCredentials(credentials, userId);
    } catch (error) {
      logger.error("Credentials invalid, re-authentication required");
      const authUrl = await this.gauth.getAuthorizationUrl(userId, {});
      const oauthServer = new OAuthServer(this.gauth);
      oauthServer.listen(4100);
      return authUrl;
    }

    return null;
  }

  private setupHandlers() {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          ...this.tools.gmail.getTools(),
          ...this.tools.calendar.getTools(),
        ],
      };
    });

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        if (typeof args !== "object" || args === null) {
          return {
            isError: true,
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    error: "arguments must be dictionary",
                    success: false,
                  },
                  null,
                  2,
                ),
              },
            ],
          };
        }

        // Special case for list_accounts tools which don't require user_id
        if (
          name === "gmail_list_accounts" ||
          name === "calendar_list_accounts"
        ) {
          try {
            // Route tool calls to appropriate handler
            let result;
            if (name.startsWith("gmail_")) {
              result = await this.tools.gmail.handleTool(name, args);
            } else if (name.startsWith("calendar_")) {
              result = await this.tools.calendar.handleTool(name, args);
            } else {
              throw new Error(`Unknown tool: ${name}`);
            }

            return { content: result };
          } catch (error) {
            logger.error(`Error handling tool ${name}:`, error as Error);
            return {
              isError: true,
              content: [
                {
                  type: "text",
                  text: JSON.stringify(
                    {
                      error: `Tool execution failed: ${(error as Error).message}`,
                      success: false,
                    },
                    null,
                    2,
                  ),
                },
              ],
            };
          }
        }

        // For all other tools, require user_id
        if (!args.user_id) {
          return {
            isError: true,
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    error: "user_id argument is missing in dictionary",
                    success: false,
                  },
                  null,
                  2,
                ),
              },
            ],
          };
        }

        let authUrl: string | null;
        try {
          authUrl = await this.setupOAuth2(args.user_id as string);
        } catch (error) {
          logger.error("OAuth2 setup failed:", error as Error);
          return {
            isError: true,
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    error: `OAuth2 setup failed: ${(error as Error).message}`,
                    success: false,
                  },
                  null,
                  2,
                ),
              },
            ],
          };
        }

        // If auth URL returned, user needs to authenticate first
        if (authUrl) {
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    success: false,
                    requires_auth: true,
                    auth_url: authUrl,
                    message: `Authentication required for ${args.user_id}. Please visit the following URL to authorize access:`,
                  },
                  null,
                  2,
                ),
              },
            ],
          };
        }

        // Route tool calls to appropriate handler
        try {
          let result;
          if (name.startsWith("gmail_")) {
            result = await this.tools.gmail.handleTool(name, args);
          } else if (name.startsWith("calendar_")) {
            result = await this.tools.calendar.handleTool(name, args);
          } else {
            throw new Error(`Unknown tool: ${name}`);
          }

          return { content: result };
        } catch (error) {
          logger.error(`Error handling tool ${name}:`, error as Error);
          return {
            isError: true,
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    error: `Tool execution failed: ${(error as Error).message}`,
                    success: false,
                  },
                  null,
                  2,
                ),
              },
            ],
          };
        }
      } catch (error) {
        logger.error("Unexpected error in call_tool:", error as Error);
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  error: `Unexpected error: ${(error as Error).message}`,
                  success: false,
                },
                null,
                2,
              ),
            },
          ],
        };
      }
    });
  }

  async start(mode: "stdio" | "http" = "stdio", httpPort: number = 4200) {
    try {
      // Initialize OAuth2 client first
      await this.gauth.initialize();

      // Initialize tools after OAuth2 is ready
      await this.initializeTools();

      // Check for existing credentials
      const accounts = await this.gauth.getAccountInfo();
      for (const account of accounts) {
        const creds = await this.gauth.getStoredCredentials(account.email);
        if (creds) {
          logger.info(`found credentials for ${account.email}`);
        }
      }

      if (mode === "http") {
        await this.startHTTP(httpPort);
      } else {
        // Start stdio transport
        const transport = new StdioServerTransport();
        logger.info("Connecting to stdio transport...");
        await this.server.connect(transport);
        logger.info("Server ready (stdio)!");
      }
    } catch (error) {
      logger.error("Server error:", error as Error);
      throw error;
    }
  }

  private async startHTTP(port: number) {
    // Map of session ID -> transport
    const transports: Record<string, StreamableHTTPServerTransport> = {};

    const httpServer = createServer(
      async (req: IncomingMessage, res: ServerResponse) => {
        const url = parseUrl(req.url || "");

        // Health check endpoint for external monitoring
        if (url.pathname === "/health") {
          res.setHeader("Access-Control-Allow-Origin", "*");
          res.setHeader("Content-Type", "application/json");
          const accounts = await this.gauth.getAccountInfo();
          const accountStatuses = [];
          for (const account of accounts) {
            const creds = await this.gauth.getStoredCredentials(account.email);
            accountStatuses.push({
              email: account.email,
              authenticated: !!creds,
              needs_auth: !creds,
            });
          }
          res.writeHead(200);
          res.end(JSON.stringify({
            status: "ok",
            server: "mcp-google-workspace",
            version: "1.0.0",
            accounts: accountStatuses,
            tools: [
              ...this.tools.gmail.getTools().map((t: any) => t.name),
              ...this.tools.calendar.getTools().map((t: any) => t.name),
            ],
          }));
          return;
        }

        // Auth URL endpoint — returns Google OAuth URL for a given email
        if (url.pathname === "/auth-url") {
          res.setHeader("Access-Control-Allow-Origin", "*");
          res.setHeader("Content-Type", "application/json");
          const query = parseQueryString(url.query || "");
          const email = query.email as string;
          if (!email) {
            res.writeHead(400);
            res.end(JSON.stringify({ success: false, error: "Missing 'email' query parameter" }));
            return;
          }
          try {
            // Check if already authenticated
            const creds = await this.gauth.getStoredCredentials(email);
            if (creds) {
              try {
                await this.gauth.getUserInfo(creds);
                res.writeHead(200);
                res.end(JSON.stringify({
                  success: true,
                  authenticated: true,
                  email,
                  message: `Already authenticated for ${email}`,
                }));
                return;
              } catch {
                // Credentials invalid, need re-auth
              }
            }
            const authUrl = await this.gauth.getAuthorizationUrl(email, {});
            // Start callback server for the redirect
            const oauthServer = new OAuthServer(this.gauth);
            oauthServer.listen(4100);
            res.writeHead(200);
            res.end(JSON.stringify({
              success: true,
              authenticated: false,
              email,
              auth_url: authUrl,
              auth_type: "google_oauth",
              callback_url: "http://localhost:4100/code",
              message: `Visit the auth_url to authenticate ${email} with Google`,
            }));
          } catch (error) {
            res.writeHead(500);
            res.end(JSON.stringify({ success: false, error: (error as Error).message }));
          }
          return;
        }

        // OAuth callback on /code (reuse existing port for convenience)
        if (url.pathname === "/code") {
          const query = parseQueryString(url.query || "");
          if (!query.code) {
            res.writeHead(400);
            res.end();
            return;
          }
          res.writeHead(200);
          res.write("Auth successful! You can close the tab!");
          res.end();
          const storage = {};
          await this.gauth.getCredentials(query.code as string, storage);
          return;
        }

        // Only handle /mcp path
        if (url.pathname !== "/mcp") {
          res.writeHead(404);
          res.end(JSON.stringify({ error: "Not found. Use /mcp endpoint." }));
          return;
        }

        // CORS headers
        res.setHeader("Access-Control-Allow-Origin", "*");
        res.setHeader(
          "Access-Control-Allow-Methods",
          "GET, POST, DELETE, OPTIONS",
        );
        res.setHeader(
          "Access-Control-Allow-Headers",
          "Content-Type, mcp-session-id",
        );
        res.setHeader("Access-Control-Expose-Headers", "mcp-session-id");

        if (req.method === "OPTIONS") {
          res.writeHead(204);
          res.end();
          return;
        }

        const sessionId = req.headers["mcp-session-id"] as string | undefined;

        if (req.method === "GET") {
          // SSE stream for existing session
          if (!sessionId || !transports[sessionId]) {
            res.writeHead(400);
            res.end("Invalid or missing session ID");
            return;
          }
          await transports[sessionId].handleRequest(req, res);
          return;
        }

        if (req.method === "DELETE") {
          // Session termination
          if (!sessionId || !transports[sessionId]) {
            res.writeHead(400);
            res.end("Invalid or missing session ID");
            return;
          }
          await transports[sessionId].handleRequest(req, res);
          return;
        }

        if (req.method === "POST") {
          // Read request body
          const body = await new Promise<string>((resolve) => {
            let data = "";
            req.on("data", (chunk: Buffer) => {
              data += chunk.toString();
            });
            req.on("end", () => resolve(data));
          });

          let parsedBody: unknown;
          try {
            parsedBody = JSON.parse(body);
          } catch {
            res.writeHead(400);
            res.end(
              JSON.stringify({
                jsonrpc: "2.0",
                error: { code: -32700, message: "Parse error" },
                id: null,
              }),
            );
            return;
          }

          let transport: StreamableHTTPServerTransport;

          if (sessionId && transports[sessionId]) {
            // Reuse existing transport
            transport = transports[sessionId];
          } else if (!sessionId && isInitializeRequest(parsedBody)) {
            // New initialization request — create new transport + server
            transport = new StreamableHTTPServerTransport({
              sessionIdGenerator: () => randomUUID(),
              onsessioninitialized: (newSessionId: string) => {
                logger.info(`Session initialized: ${newSessionId}`);
                transports[newSessionId] = transport;
              },
            });

            transport.onclose = () => {
              const sid = transport.sessionId;
              if (sid && transports[sid]) {
                logger.info(`Session closed: ${sid}`);
                delete transports[sid];
              }
            };

            // Create a fresh MCP Server instance for this session and connect
            const sessionServer = new Server(
              { name: "mcp-google-workspace", version: "1.0.0" },
              { capabilities: { tools: {} } },
            );
            this.setupHandlersOnServer(sessionServer);
            await sessionServer.connect(transport);
          } else {
            res.writeHead(400);
            res.end(
              JSON.stringify({
                jsonrpc: "2.0",
                error: {
                  code: -32000,
                  message: "Bad Request: No valid session ID provided",
                },
                id: null,
              }),
            );
            return;
          }

          await transport.handleRequest(req, res, parsedBody);
          return;
        }

        res.writeHead(405);
        res.end("Method not allowed");
      },
    );

    httpServer.listen(port, () => {
      logger.info(`MCP Streamable HTTP Server listening on port ${port}`);
      logger.info(`Endpoint: http://localhost:${port}/mcp`);
    });

    process.on("SIGINT", async () => {
      logger.info("Shutting down...");
      for (const sid in transports) {
        await transports[sid].close();
        delete transports[sid];
      }
      httpServer.close();
      process.exit(0);
    });
  }

  /**
   * Set up tool handlers on a given Server instance.
   * Used by HTTP mode to create per-session server instances.
   */
  private setupHandlersOnServer(server: Server) {
    server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          ...this.tools.gmail.getTools(),
          ...this.tools.calendar.getTools(),
        ],
      };
    });

    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        if (typeof args !== "object" || args === null) {
          return {
            isError: true,
            content: [
              {
                type: "text" as const,
                text: JSON.stringify(
                  { error: "arguments must be dictionary", success: false },
                  null,
                  2,
                ),
              },
            ],
          };
        }

        // list_accounts tools don't require user_id
        if (
          name === "gmail_list_accounts" ||
          name === "calendar_list_accounts"
        ) {
          try {
            let result;
            if (name.startsWith("gmail_")) {
              result = await this.tools.gmail.handleTool(name, args);
            } else if (name.startsWith("calendar_")) {
              result = await this.tools.calendar.handleTool(name, args);
            } else {
              throw new Error(`Unknown tool: ${name}`);
            }
            return { content: result };
          } catch (error) {
            logger.error(`Error handling tool ${name}:`, error as Error);
            return {
              isError: true,
              content: [
                {
                  type: "text" as const,
                  text: JSON.stringify(
                    {
                      error: `Tool execution failed: ${(error as Error).message}`,
                      success: false,
                    },
                    null,
                    2,
                  ),
                },
              ],
            };
          }
        }

        // All other tools require user_id
        if (!args.user_id) {
          return {
            isError: true,
            content: [
              {
                type: "text" as const,
                text: JSON.stringify(
                  {
                    error: "user_id argument is missing in dictionary",
                    success: false,
                  },
                  null,
                  2,
                ),
              },
            ],
          };
        }

        let authUrl: string | null;
        try {
          authUrl = await this.setupOAuth2(args.user_id as string);
        } catch (error) {
          logger.error("OAuth2 setup failed:", error as Error);
          return {
            isError: true,
            content: [
              {
                type: "text" as const,
                text: JSON.stringify(
                  {
                    error: `OAuth2 setup failed: ${(error as Error).message}`,
                    success: false,
                  },
                  null,
                  2,
                ),
              },
            ],
          };
        }

        // If auth URL returned, user needs to authenticate first
        if (authUrl) {
          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify(
                  {
                    success: false,
                    requires_auth: true,
                    auth_url: authUrl,
                    message: `Authentication required for ${args.user_id}. Please visit the following URL to authorize access:`,
                  },
                  null,
                  2,
                ),
              },
            ],
          };
        }

        try {
          let result;
          if (name.startsWith("gmail_")) {
            result = await this.tools.gmail.handleTool(name, args);
          } else if (name.startsWith("calendar_")) {
            result = await this.tools.calendar.handleTool(name, args);
          } else {
            throw new Error(`Unknown tool: ${name}`);
          }
          return { content: result };
        } catch (error) {
          logger.error(`Error handling tool ${name}:`, error as Error);
          return {
            isError: true,
            content: [
              {
                type: "text" as const,
                text: JSON.stringify(
                  {
                    error: `Tool execution failed: ${(error as Error).message}`,
                    success: false,
                  },
                  null,
                  2,
                ),
              },
            ],
          };
        }
      } catch (error) {
        logger.error("Unexpected error in call_tool:", error as Error);
        return {
          isError: true,
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  error: `Unexpected error: ${(error as Error).message}`,
                  success: false,
                },
                null,
                2,
              ),
            },
          ],
        };
      }
    });
  }
}

// Parse command line arguments
const { values } = parseArgs({
  args: process.argv.slice(2),
  options: {
    "gauth-file": { type: "string", default: "./.gauth.json" },
    "accounts-file": { type: "string", default: "./.accounts.json" },
    "credentials-dir": { type: "string", default: "." },
    http: { type: "boolean", default: false },
    port: { type: "string", default: "4200" },
  },
});

const config: ServerConfig = {
  gauthFile: values["gauth-file"] as string,
  accountsFile: values["accounts-file"] as string,
  credentialsDir: values["credentials-dir"] as string,
};

const transportMode = values["http"] ? "http" : "stdio";
const httpPort = parseInt(values["port"] as string, 10) || 4200;

// Start the server
const wsServer = new GoogleWorkspaceServer(config);
wsServer.start(transportMode as "stdio" | "http", httpPort).catch((error) => {
  logger.error("Fatal error:", error as Error);
  process.exit(1);
});
