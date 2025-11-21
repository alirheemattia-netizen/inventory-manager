// server/_core/index.ts
import "dotenv/config";
import express2 from "express";
import { createServer } from "http";
import net from "net";
import { createExpressMiddleware } from "@trpc/server/adapters/express";

// shared/const.ts
var COOKIE_NAME = "app_session_id";
var ONE_YEAR_MS = 1e3 * 60 * 60 * 24 * 365;
var AXIOS_TIMEOUT_MS = 3e4;
var UNAUTHED_ERR_MSG = "Please login (10001)";
var NOT_ADMIN_ERR_MSG = "You do not have required permission (10002)";

// server/db.ts
import { eq, and, gte, lte, desc } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";

// drizzle/schema.ts
import { int, mysqlEnum, mysqlTable, text, timestamp, varchar } from "drizzle-orm/mysql-core";
var users = mysqlTable("users", {
  id: int("id").autoincrement().primaryKey(),
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull()
});
var categories = mysqlTable("categories", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull(),
  name: varchar("name", { length: 255 }).notNull(),
  // مثل: "خطوط SIM"، "دولار"، "فيزا"، إلخ
  description: text("description"),
  type: mysqlEnum("type", [
    "sim_lines",
    "currency",
    "visa",
    "electronic_cards",
    "device_asia",
    "device_ether"
  ]).notNull(),
  initialBalance: int("initialBalance").default(0).notNull(),
  // الرصيد الأولي
  currentBalance: int("currentBalance").default(0).notNull(),
  // الرصيد الحالي
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull()
});
var transactions = mysqlTable("transactions", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull(),
  categoryId: int("categoryId").notNull(),
  type: mysqlEnum("type", ["add", "sell"]).notNull(),
  // إضافة أو بيع
  amount: int("amount").notNull(),
  // المبلغ أو الكمية
  description: text("description"),
  // ملاحظات إضافية
  balanceBefore: int("balanceBefore").notNull(),
  // الرصيد قبل العملية
  balanceAfter: int("balanceAfter").notNull(),
  // الرصيد بعد العملية
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  transactionDate: timestamp("transactionDate").defaultNow().notNull()
  // تاريخ العملية
});
var dailyReports = mysqlTable("dailyReports", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull(),
  categoryId: int("categoryId").notNull(),
  reportDate: varchar("reportDate", { length: 10 }).notNull(),
  // YYYY-MM-DD
  openingBalance: int("openingBalance").notNull(),
  // الرصيد الافتتاحي
  totalAdded: int("totalAdded").default(0).notNull(),
  // إجمالي المضاف
  totalSold: int("totalSold").default(0).notNull(),
  // إجمالي المباع
  closingBalance: int("closingBalance").notNull(),
  // الرصيد الختامي
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull()
});
var monthlyReports = mysqlTable("monthlyReports", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull(),
  categoryId: int("categoryId").notNull(),
  reportMonth: varchar("reportMonth", { length: 7 }).notNull(),
  // YYYY-MM
  openingBalance: int("openingBalance").notNull(),
  // الرصيد الافتتاحي
  totalAdded: int("totalAdded").default(0).notNull(),
  // إجمالي المضاف
  totalSold: int("totalSold").default(0).notNull(),
  // إجمالي المباع
  closingBalance: int("closingBalance").notNull(),
  // الرصيد الختامي
  totalTransactions: int("totalTransactions").default(0).notNull(),
  // عدد العمليات
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull()
});

// server/_core/env.ts
var ENV = {
  appId: process.env.VITE_APP_ID ?? "",
  cookieSecret: process.env.JWT_SECRET ?? "",
  databaseUrl: process.env.DATABASE_URL ?? "",
  oAuthServerUrl: process.env.OAUTH_SERVER_URL ?? "",
  ownerOpenId: process.env.OWNER_OPEN_ID ?? "",
  isProduction: process.env.NODE_ENV === "production",
  forgeApiUrl: process.env.BUILT_IN_FORGE_API_URL ?? "",
  forgeApiKey: process.env.BUILT_IN_FORGE_API_KEY ?? ""
};

// server/db.ts
var _db = null;
async function getDb() {
  if (!_db && process.env.DATABASE_URL) {
    try {
      _db = drizzle(process.env.DATABASE_URL);
    } catch (error) {
      console.warn("[Database] Failed to connect:", error);
      _db = null;
    }
  }
  return _db;
}
async function upsertUser(user) {
  if (!user.openId) {
    throw new Error("User openId is required for upsert");
  }
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot upsert user: database not available");
    return;
  }
  try {
    const values = {
      openId: user.openId
    };
    const updateSet = {};
    const textFields = ["name", "email", "loginMethod"];
    const assignNullable = (field) => {
      const value = user[field];
      if (value === void 0) return;
      const normalized = value ?? null;
      values[field] = normalized;
      updateSet[field] = normalized;
    };
    textFields.forEach(assignNullable);
    if (user.lastSignedIn !== void 0) {
      values.lastSignedIn = user.lastSignedIn;
      updateSet.lastSignedIn = user.lastSignedIn;
    }
    if (user.role !== void 0) {
      values.role = user.role;
      updateSet.role = user.role;
    } else if (user.openId === ENV.ownerOpenId) {
      values.role = "admin";
      updateSet.role = "admin";
    }
    if (!values.lastSignedIn) {
      values.lastSignedIn = /* @__PURE__ */ new Date();
    }
    if (Object.keys(updateSet).length === 0) {
      updateSet.lastSignedIn = /* @__PURE__ */ new Date();
    }
    await db.insert(users).values(values).onDuplicateKeyUpdate({
      set: updateSet
    });
  } catch (error) {
    console.error("[Database] Failed to upsert user:", error);
    throw error;
  }
}
async function getUserByOpenId(openId) {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get user: database not available");
    return void 0;
  }
  const result = await db.select().from(users).where(eq(users.openId, openId)).limit(1);
  return result.length > 0 ? result[0] : void 0;
}
async function createCategory(userId, data) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const result = await db.insert(categories).values({
    userId,
    name: data.name,
    description: data.description,
    type: data.type,
    initialBalance: data.initialBalance || 0,
    currentBalance: data.initialBalance || 0
  });
  return result;
}
async function getUserCategories(userId) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(categories).where(eq(categories.userId, userId));
}
async function getCategory(categoryId, userId) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const result = await db.select().from(categories).where(
    and(eq(categories.id, categoryId), eq(categories.userId, userId))
  );
  return result.length > 0 ? result[0] : null;
}
async function addTransaction(userId, data) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const category = await getCategory(data.categoryId, userId);
  if (!category) throw new Error("Category not found");
  const balanceBefore = category.currentBalance;
  const balanceAfter = data.type === "add" ? balanceBefore + data.amount : balanceBefore - data.amount;
  if (balanceAfter < 0) {
    throw new Error("Insufficient balance");
  }
  const transactionResult = await db.insert(transactions).values({
    userId,
    categoryId: data.categoryId,
    type: data.type,
    amount: data.amount,
    description: data.description,
    balanceBefore,
    balanceAfter,
    transactionDate: /* @__PURE__ */ new Date()
  });
  await db.update(categories).set({ currentBalance: balanceAfter }).where(eq(categories.id, data.categoryId));
  return { transactionResult, balanceAfter };
}
async function getCategoryTransactions(categoryId, userId, limit = 100) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(transactions).where(and(eq(transactions.categoryId, categoryId), eq(transactions.userId, userId))).orderBy(desc(transactions.createdAt)).limit(limit);
}
async function getDailyReport(userId, categoryId, reportDate) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const result = await db.select().from(dailyReports).where(
    and(
      eq(dailyReports.userId, userId),
      eq(dailyReports.categoryId, categoryId),
      eq(dailyReports.reportDate, reportDate)
    )
  );
  return result.length > 0 ? result[0] : null;
}
async function upsertDailyReport(userId, categoryId, reportDate) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const startDate = /* @__PURE__ */ new Date(`${reportDate}T00:00:00Z`);
  const endDate = /* @__PURE__ */ new Date(`${reportDate}T23:59:59Z`);
  const dayTransactions = await db.select().from(transactions).where(
    and(
      eq(transactions.userId, userId),
      eq(transactions.categoryId, categoryId),
      gte(transactions.transactionDate, startDate),
      lte(transactions.transactionDate, endDate)
    )
  );
  let totalAdded = 0;
  let totalSold = 0;
  let openingBalance = 0;
  let closingBalance = 0;
  if (dayTransactions.length > 0) {
    openingBalance = dayTransactions[0].balanceBefore;
    closingBalance = dayTransactions[dayTransactions.length - 1].balanceAfter;
    dayTransactions.forEach((tx) => {
      if (tx.type === "add") {
        totalAdded += tx.amount;
      } else {
        totalSold += tx.amount;
      }
    });
  } else {
    const category = await getCategory(categoryId, userId);
    if (category) {
      openingBalance = category.currentBalance;
      closingBalance = category.currentBalance;
    }
  }
  const existingReport = await getDailyReport(userId, categoryId, reportDate);
  if (existingReport) {
    await db.update(dailyReports).set({
      openingBalance,
      totalAdded,
      totalSold,
      closingBalance
    }).where(eq(dailyReports.id, existingReport.id));
  } else {
    await db.insert(dailyReports).values({
      userId,
      categoryId,
      reportDate,
      openingBalance,
      totalAdded,
      totalSold,
      closingBalance
    });
  }
}
async function getMonthlyReport(userId, categoryId, reportMonth) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const result = await db.select().from(monthlyReports).where(
    and(
      eq(monthlyReports.userId, userId),
      eq(monthlyReports.categoryId, categoryId),
      eq(monthlyReports.reportMonth, reportMonth)
    )
  );
  return result.length > 0 ? result[0] : null;
}
async function upsertMonthlyReport(userId, categoryId, reportMonth) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const [year, month] = reportMonth.split("-");
  const startDate = /* @__PURE__ */ new Date(`${year}-${month}-01T00:00:00Z`);
  const endDate = new Date(startDate);
  endDate.setMonth(endDate.getMonth() + 1);
  const monthTransactions = await db.select().from(transactions).where(
    and(
      eq(transactions.userId, userId),
      eq(transactions.categoryId, categoryId),
      gte(transactions.transactionDate, startDate),
      lte(transactions.transactionDate, endDate)
    )
  );
  let totalAdded = 0;
  let totalSold = 0;
  let openingBalance = 0;
  let closingBalance = 0;
  if (monthTransactions.length > 0) {
    openingBalance = monthTransactions[0].balanceBefore;
    closingBalance = monthTransactions[monthTransactions.length - 1].balanceAfter;
    monthTransactions.forEach((tx) => {
      if (tx.type === "add") {
        totalAdded += tx.amount;
      } else {
        totalSold += tx.amount;
      }
    });
  } else {
    const category = await getCategory(categoryId, userId);
    if (category) {
      openingBalance = category.currentBalance;
      closingBalance = category.currentBalance;
    }
  }
  const existingReport = await getMonthlyReport(userId, categoryId, reportMonth);
  if (existingReport) {
    await db.update(monthlyReports).set({
      openingBalance,
      totalAdded,
      totalSold,
      closingBalance,
      totalTransactions: monthTransactions.length
    }).where(eq(monthlyReports.id, existingReport.id));
  } else {
    await db.insert(monthlyReports).values({
      userId,
      categoryId,
      reportMonth,
      openingBalance,
      totalAdded,
      totalSold,
      closingBalance,
      totalTransactions: monthTransactions.length
    });
  }
}
async function getMonthDailyReports(userId, categoryId, reportMonth) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return await db.select().from(dailyReports).where(
    and(
      eq(dailyReports.userId, userId),
      eq(dailyReports.categoryId, categoryId),
      gte(dailyReports.reportDate, `${reportMonth}-01`),
      lte(dailyReports.reportDate, `${reportMonth}-31`)
    )
  ).orderBy(desc(dailyReports.reportDate));
}

// server/_core/cookies.ts
function isSecureRequest(req) {
  if (req.protocol === "https") return true;
  const forwardedProto = req.headers["x-forwarded-proto"];
  if (!forwardedProto) return false;
  const protoList = Array.isArray(forwardedProto) ? forwardedProto : forwardedProto.split(",");
  return protoList.some((proto) => proto.trim().toLowerCase() === "https");
}
function getSessionCookieOptions(req) {
  return {
    httpOnly: true,
    path: "/",
    sameSite: "none",
    secure: isSecureRequest(req)
  };
}

// shared/_core/errors.ts
var HttpError = class extends Error {
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
    this.name = "HttpError";
  }
};
var ForbiddenError = (msg) => new HttpError(403, msg);

// server/_core/sdk.ts
import axios from "axios";
import { parse as parseCookieHeader } from "cookie";
import { SignJWT, jwtVerify } from "jose";
var isNonEmptyString = (value) => typeof value === "string" && value.length > 0;
var EXCHANGE_TOKEN_PATH = `/webdev.v1.WebDevAuthPublicService/ExchangeToken`;
var GET_USER_INFO_PATH = `/webdev.v1.WebDevAuthPublicService/GetUserInfo`;
var GET_USER_INFO_WITH_JWT_PATH = `/webdev.v1.WebDevAuthPublicService/GetUserInfoWithJwt`;
var OAuthService = class {
  constructor(client) {
    this.client = client;
    console.log("[OAuth] Initialized with baseURL:", ENV.oAuthServerUrl);
    if (!ENV.oAuthServerUrl) {
      console.error(
        "[OAuth] ERROR: OAUTH_SERVER_URL is not configured! Set OAUTH_SERVER_URL environment variable."
      );
    }
  }
  decodeState(state) {
    const redirectUri = atob(state);
    return redirectUri;
  }
  async getTokenByCode(code, state) {
    const payload = {
      clientId: ENV.appId,
      grantType: "authorization_code",
      code,
      redirectUri: this.decodeState(state)
    };
    const { data } = await this.client.post(
      EXCHANGE_TOKEN_PATH,
      payload
    );
    return data;
  }
  async getUserInfoByToken(token) {
    const { data } = await this.client.post(
      GET_USER_INFO_PATH,
      {
        accessToken: token.accessToken
      }
    );
    return data;
  }
};
var createOAuthHttpClient = () => axios.create({
  baseURL: ENV.oAuthServerUrl,
  timeout: AXIOS_TIMEOUT_MS
});
var SDKServer = class {
  client;
  oauthService;
  constructor(client = createOAuthHttpClient()) {
    this.client = client;
    this.oauthService = new OAuthService(this.client);
  }
  deriveLoginMethod(platforms, fallback) {
    if (fallback && fallback.length > 0) return fallback;
    if (!Array.isArray(platforms) || platforms.length === 0) return null;
    const set = new Set(
      platforms.filter((p) => typeof p === "string")
    );
    if (set.has("REGISTERED_PLATFORM_EMAIL")) return "email";
    if (set.has("REGISTERED_PLATFORM_GOOGLE")) return "google";
    if (set.has("REGISTERED_PLATFORM_APPLE")) return "apple";
    if (set.has("REGISTERED_PLATFORM_MICROSOFT") || set.has("REGISTERED_PLATFORM_AZURE"))
      return "microsoft";
    if (set.has("REGISTERED_PLATFORM_GITHUB")) return "github";
    const first = Array.from(set)[0];
    return first ? first.toLowerCase() : null;
  }
  /**
   * Exchange OAuth authorization code for access token
   * @example
   * const tokenResponse = await sdk.exchangeCodeForToken(code, state);
   */
  async exchangeCodeForToken(code, state) {
    return this.oauthService.getTokenByCode(code, state);
  }
  /**
   * Get user information using access token
   * @example
   * const userInfo = await sdk.getUserInfo(tokenResponse.accessToken);
   */
  async getUserInfo(accessToken) {
    const data = await this.oauthService.getUserInfoByToken({
      accessToken
    });
    const loginMethod = this.deriveLoginMethod(
      data?.platforms,
      data?.platform ?? data.platform ?? null
    );
    return {
      ...data,
      platform: loginMethod,
      loginMethod
    };
  }
  parseCookies(cookieHeader) {
    if (!cookieHeader) {
      return /* @__PURE__ */ new Map();
    }
    const parsed = parseCookieHeader(cookieHeader);
    return new Map(Object.entries(parsed));
  }
  getSessionSecret() {
    const secret = ENV.cookieSecret;
    return new TextEncoder().encode(secret);
  }
  /**
   * Create a session token for a Manus user openId
   * @example
   * const sessionToken = await sdk.createSessionToken(userInfo.openId);
   */
  async createSessionToken(openId, options = {}) {
    return this.signSession(
      {
        openId,
        appId: ENV.appId,
        name: options.name || ""
      },
      options
    );
  }
  async signSession(payload, options = {}) {
    const issuedAt = Date.now();
    const expiresInMs = options.expiresInMs ?? ONE_YEAR_MS;
    const expirationSeconds = Math.floor((issuedAt + expiresInMs) / 1e3);
    const secretKey = this.getSessionSecret();
    return new SignJWT({
      openId: payload.openId,
      appId: payload.appId,
      name: payload.name
    }).setProtectedHeader({ alg: "HS256", typ: "JWT" }).setExpirationTime(expirationSeconds).sign(secretKey);
  }
  async verifySession(cookieValue) {
    if (!cookieValue) {
      console.warn("[Auth] Missing session cookie");
      return null;
    }
    try {
      const secretKey = this.getSessionSecret();
      const { payload } = await jwtVerify(cookieValue, secretKey, {
        algorithms: ["HS256"]
      });
      const { openId, appId, name } = payload;
      if (!isNonEmptyString(openId) || !isNonEmptyString(appId) || !isNonEmptyString(name)) {
        console.warn("[Auth] Session payload missing required fields");
        return null;
      }
      return {
        openId,
        appId,
        name
      };
    } catch (error) {
      console.warn("[Auth] Session verification failed", String(error));
      return null;
    }
  }
  async getUserInfoWithJwt(jwtToken) {
    const payload = {
      jwtToken,
      projectId: ENV.appId
    };
    const { data } = await this.client.post(
      GET_USER_INFO_WITH_JWT_PATH,
      payload
    );
    const loginMethod = this.deriveLoginMethod(
      data?.platforms,
      data?.platform ?? data.platform ?? null
    );
    return {
      ...data,
      platform: loginMethod,
      loginMethod
    };
  }
  async authenticateRequest(req) {
    const cookies = this.parseCookies(req.headers.cookie);
    const sessionCookie = cookies.get(COOKIE_NAME);
    const session = await this.verifySession(sessionCookie);
    if (!session) {
      throw ForbiddenError("Invalid session cookie");
    }
    const sessionUserId = session.openId;
    const signedInAt = /* @__PURE__ */ new Date();
    let user = await getUserByOpenId(sessionUserId);
    if (!user) {
      try {
        const userInfo = await this.getUserInfoWithJwt(sessionCookie ?? "");
        await upsertUser({
          openId: userInfo.openId,
          name: userInfo.name || null,
          email: userInfo.email ?? null,
          loginMethod: userInfo.loginMethod ?? userInfo.platform ?? null,
          lastSignedIn: signedInAt
        });
        user = await getUserByOpenId(userInfo.openId);
      } catch (error) {
        console.error("[Auth] Failed to sync user from OAuth:", error);
        throw ForbiddenError("Failed to sync user info");
      }
    }
    if (!user) {
      throw ForbiddenError("User not found");
    }
    await upsertUser({
      openId: user.openId,
      lastSignedIn: signedInAt
    });
    return user;
  }
};
var sdk = new SDKServer();

// server/_core/oauth.ts
function getQueryParam(req, key) {
  const value = req.query[key];
  return typeof value === "string" ? value : void 0;
}
function registerOAuthRoutes(app) {
  app.get("/api/oauth/callback", async (req, res) => {
    const code = getQueryParam(req, "code");
    const state = getQueryParam(req, "state");
    if (!code || !state) {
      res.status(400).json({ error: "code and state are required" });
      return;
    }
    try {
      const tokenResponse = await sdk.exchangeCodeForToken(code, state);
      const userInfo = await sdk.getUserInfo(tokenResponse.accessToken);
      if (!userInfo.openId) {
        res.status(400).json({ error: "openId missing from user info" });
        return;
      }
      await upsertUser({
        openId: userInfo.openId,
        name: userInfo.name || null,
        email: userInfo.email ?? null,
        loginMethod: userInfo.loginMethod ?? userInfo.platform ?? null,
        lastSignedIn: /* @__PURE__ */ new Date()
      });
      const sessionToken = await sdk.createSessionToken(userInfo.openId, {
        name: userInfo.name || "",
        expiresInMs: ONE_YEAR_MS
      });
      const cookieOptions = getSessionCookieOptions(req);
      res.cookie(COOKIE_NAME, sessionToken, { ...cookieOptions, maxAge: ONE_YEAR_MS });
      res.redirect(302, "/");
    } catch (error) {
      console.error("[OAuth] Callback failed", error);
      res.status(500).json({ error: "OAuth callback failed" });
    }
  });
}

// server/_core/systemRouter.ts
import { z } from "zod";

// server/_core/notification.ts
import { TRPCError } from "@trpc/server";
var TITLE_MAX_LENGTH = 1200;
var CONTENT_MAX_LENGTH = 2e4;
var trimValue = (value) => value.trim();
var isNonEmptyString2 = (value) => typeof value === "string" && value.trim().length > 0;
var buildEndpointUrl = (baseUrl) => {
  const normalizedBase = baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
  return new URL(
    "webdevtoken.v1.WebDevService/SendNotification",
    normalizedBase
  ).toString();
};
var validatePayload = (input) => {
  if (!isNonEmptyString2(input.title)) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: "Notification title is required."
    });
  }
  if (!isNonEmptyString2(input.content)) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: "Notification content is required."
    });
  }
  const title = trimValue(input.title);
  const content = trimValue(input.content);
  if (title.length > TITLE_MAX_LENGTH) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: `Notification title must be at most ${TITLE_MAX_LENGTH} characters.`
    });
  }
  if (content.length > CONTENT_MAX_LENGTH) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: `Notification content must be at most ${CONTENT_MAX_LENGTH} characters.`
    });
  }
  return { title, content };
};
async function notifyOwner(payload) {
  const { title, content } = validatePayload(payload);
  if (!ENV.forgeApiUrl) {
    throw new TRPCError({
      code: "INTERNAL_SERVER_ERROR",
      message: "Notification service URL is not configured."
    });
  }
  if (!ENV.forgeApiKey) {
    throw new TRPCError({
      code: "INTERNAL_SERVER_ERROR",
      message: "Notification service API key is not configured."
    });
  }
  const endpoint = buildEndpointUrl(ENV.forgeApiUrl);
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${ENV.forgeApiKey}`,
        "content-type": "application/json",
        "connect-protocol-version": "1"
      },
      body: JSON.stringify({ title, content })
    });
    if (!response.ok) {
      const detail = await response.text().catch(() => "");
      console.warn(
        `[Notification] Failed to notify owner (${response.status} ${response.statusText})${detail ? `: ${detail}` : ""}`
      );
      return false;
    }
    return true;
  } catch (error) {
    console.warn("[Notification] Error calling notification service:", error);
    return false;
  }
}

// server/_core/trpc.ts
import { initTRPC, TRPCError as TRPCError2 } from "@trpc/server";
import superjson from "superjson";
var t = initTRPC.context().create({
  transformer: superjson
});
var router = t.router;
var publicProcedure = t.procedure;
var requireUser = t.middleware(async (opts) => {
  const { ctx, next } = opts;
  if (!ctx.user) {
    throw new TRPCError2({ code: "UNAUTHORIZED", message: UNAUTHED_ERR_MSG });
  }
  return next({
    ctx: {
      ...ctx,
      user: ctx.user
    }
  });
});
var protectedProcedure = t.procedure.use(requireUser);
var adminProcedure = t.procedure.use(
  t.middleware(async (opts) => {
    const { ctx, next } = opts;
    if (!ctx.user || ctx.user.role !== "admin") {
      throw new TRPCError2({ code: "FORBIDDEN", message: NOT_ADMIN_ERR_MSG });
    }
    return next({
      ctx: {
        ...ctx,
        user: ctx.user
      }
    });
  })
);

// server/_core/systemRouter.ts
var systemRouter = router({
  health: publicProcedure.input(
    z.object({
      timestamp: z.number().min(0, "timestamp cannot be negative")
    })
  ).query(() => ({
    ok: true
  })),
  notifyOwner: adminProcedure.input(
    z.object({
      title: z.string().min(1, "title is required"),
      content: z.string().min(1, "content is required")
    })
  ).mutation(async ({ input }) => {
    const delivered = await notifyOwner(input);
    return {
      success: delivered
    };
  })
});

// server/routers.ts
import { z as z2 } from "zod";
var appRouter = router({
  system: systemRouter,
  auth: router({
    me: publicProcedure.query((opts) => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return {
        success: true
      };
    })
  }),
  // الفئات (الأصناف)
  categories: router({
    /**
     * إنشاء فئة جديدة
     */
    create: protectedProcedure.input(
      z2.object({
        name: z2.string().min(1, "\u0627\u0633\u0645 \u0627\u0644\u0641\u0626\u0629 \u0645\u0637\u0644\u0648\u0628"),
        description: z2.string().optional(),
        type: z2.enum([
          "sim_lines",
          "currency",
          "visa",
          "electronic_cards",
          "device_asia",
          "device_ether"
        ]),
        initialBalance: z2.number().int().default(0)
      })
    ).mutation(async ({ ctx, input }) => {
      if (!ctx.user) throw new Error("Not authenticated");
      return await createCategory(ctx.user.id, input);
    }),
    /**
     * الحصول على جميع الفئات للمستخدم الحالي
     */
    list: protectedProcedure.query(async ({ ctx }) => {
      if (!ctx.user) throw new Error("Not authenticated");
      return await getUserCategories(ctx.user.id);
    }),
    /**
     * الحصول على فئة واحدة
     */
    get: protectedProcedure.input(z2.object({ categoryId: z2.number().int() })).query(async ({ ctx, input }) => {
      if (!ctx.user) throw new Error("Not authenticated");
      return await getCategory(input.categoryId, ctx.user.id);
    })
  }),
  // العمليات (المعاملات)
  transactions: router({
    /**
     * إضافة عملية جديدة (إضافة أو بيع)
     */
    add: protectedProcedure.input(
      z2.object({
        categoryId: z2.number().int(),
        type: z2.enum(["add", "sell"]),
        amount: z2.number().int().positive("\u0627\u0644\u0645\u0628\u0644\u063A \u064A\u062C\u0628 \u0623\u0646 \u064A\u0643\u0648\u0646 \u0645\u0648\u062C\u0628"),
        description: z2.string().optional()
      })
    ).mutation(async ({ ctx, input }) => {
      if (!ctx.user) throw new Error("Not authenticated");
      const result = await addTransaction(ctx.user.id, input);
      const now = /* @__PURE__ */ new Date();
      const reportDate = now.toISOString().split("T")[0];
      const reportMonth = reportDate.substring(0, 7);
      await upsertDailyReport(ctx.user.id, input.categoryId, reportDate);
      await upsertMonthlyReport(ctx.user.id, input.categoryId, reportMonth);
      return result;
    }),
    /**
     * الحصول على العمليات لفئة معينة
     */
    list: protectedProcedure.input(
      z2.object({
        categoryId: z2.number().int(),
        limit: z2.number().int().default(100)
      })
    ).query(async ({ ctx, input }) => {
      if (!ctx.user) throw new Error("Not authenticated");
      return await getCategoryTransactions(input.categoryId, ctx.user.id, input.limit);
    })
  }),
  // التقارير
  reports: router({
    /**
     * الحصول على التقرير اليومي
     */
    daily: protectedProcedure.input(
      z2.object({
        categoryId: z2.number().int(),
        reportDate: z2.string()
        // YYYY-MM-DD
      })
    ).query(async ({ ctx, input }) => {
      if (!ctx.user) throw new Error("Not authenticated");
      return await getDailyReport(ctx.user.id, input.categoryId, input.reportDate);
    }),
    /**
     * الحصول على التقرير الشهري
     */
    monthly: protectedProcedure.input(
      z2.object({
        categoryId: z2.number().int(),
        reportMonth: z2.string()
        // YYYY-MM
      })
    ).query(async ({ ctx, input }) => {
      if (!ctx.user) throw new Error("Not authenticated");
      return await getMonthlyReport(ctx.user.id, input.categoryId, input.reportMonth);
    }),
    /**
     * الحصول على جميع التقارير اليومية لشهر معين
     */
    monthlyDetails: protectedProcedure.input(
      z2.object({
        categoryId: z2.number().int(),
        reportMonth: z2.string()
        // YYYY-MM
      })
    ).query(async ({ ctx, input }) => {
      if (!ctx.user) throw new Error("Not authenticated");
      return await getMonthDailyReports(ctx.user.id, input.categoryId, input.reportMonth);
    })
  })
});

// server/_core/context.ts
async function createContext(opts) {
  let user = null;
  try {
    user = await sdk.authenticateRequest(opts.req);
  } catch (error) {
    user = null;
  }
  return {
    req: opts.req,
    res: opts.res,
    user
  };
}

// server/_core/vite.ts
import express from "express";
import fs from "fs";
import { nanoid } from "nanoid";
import path2 from "path";
import { createServer as createViteServer } from "vite";

// vite.config.ts
import { jsxLocPlugin } from "@builder.io/vite-plugin-jsx-loc";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import path from "path";
import { defineConfig } from "vite";
import { vitePluginManusRuntime } from "vite-plugin-manus-runtime";
var plugins = [react(), tailwindcss(), jsxLocPlugin(), vitePluginManusRuntime()];
var vite_config_default = defineConfig({
  plugins,
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "client", "src"),
      "@shared": path.resolve(import.meta.dirname, "shared"),
      "@assets": path.resolve(import.meta.dirname, "attached_assets")
    }
  },
  envDir: path.resolve(import.meta.dirname),
  root: path.resolve(import.meta.dirname, "client"),
  publicDir: path.resolve(import.meta.dirname, "client", "public"),
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true
  },
  server: {
    host: true,
    allowedHosts: [
      ".manuspre.computer",
      ".manus.computer",
      ".manus-asia.computer",
      ".manuscomputer.ai",
      ".manusvm.computer",
      "localhost",
      "127.0.0.1"
    ],
    fs: {
      strict: true,
      deny: ["**/.*"]
    }
  }
});

// server/_core/vite.ts
async function setupVite(app, server) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    server: serverOptions,
    appType: "custom"
  });
  app.use(vite.middlewares);
  app.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path2.resolve(
        import.meta.dirname,
        "../..",
        "client",
        "index.html"
      );
      let template = await fs.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app) {
  const distPath = process.env.NODE_ENV === "development" ? path2.resolve(import.meta.dirname, "../..", "dist", "public") : path2.resolve(import.meta.dirname, "public");
  if (!fs.existsSync(distPath)) {
    console.error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app.use(express.static(distPath));
  app.use("*", (_req, res) => {
    res.sendFile(path2.resolve(distPath, "index.html"));
  });
}

// server/_core/index.ts
function isPortAvailable(port) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(port, () => {
      server.close(() => resolve(true));
    });
    server.on("error", () => resolve(false));
  });
}
async function findAvailablePort(startPort = 3e3) {
  for (let port = startPort; port < startPort + 20; port++) {
    if (await isPortAvailable(port)) {
      return port;
    }
  }
  throw new Error(`No available port found starting from ${startPort}`);
}
async function startServer() {
  const app = express2();
  const server = createServer(app);
  app.use(express2.json({ limit: "50mb" }));
  app.use(express2.urlencoded({ limit: "50mb", extended: true }));
  registerOAuthRoutes(app);
  app.use(
    "/api/trpc",
    createExpressMiddleware({
      router: appRouter,
      createContext
    })
  );
  if (process.env.NODE_ENV === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }
  const preferredPort = parseInt(process.env.PORT || "3000");
  const port = await findAvailablePort(preferredPort);
  if (port !== preferredPort) {
    console.log(`Port ${preferredPort} is busy, using port ${port} instead`);
  }
  server.listen(port, () => {
    console.log(`Server running on http://localhost:${port}/`);
  });
}
startServer().catch(console.error);
