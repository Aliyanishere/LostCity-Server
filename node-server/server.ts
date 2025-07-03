import cors from "cors";
import express from "express";
import cookieParser from "cookie-parser";
import type { Request, Response, NextFunction, RequestHandler } from "express";
import { CivicAuth, CookieStorage } from "@civic/auth/server";

// Extend Express Request interface to include storage and civicAuth
declare global {
  namespace Express {
    interface Request {
      storage?: CookieStorage;
      civicAuth?: CivicAuth;
    }
  }
}

(async () => {
  const app = express();

  app.use(
    cors({
      origin: "http://localhost",
      credentials: true,
      methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      maxAge: 3600,
      optionsSuccessStatus: 200,
    })
  );

  const config = {
    clientId: "e79e68ce-48e0-47e5-83b4-73b316d8fa35", // Client ID from auth.civic.com
    redirectUrl: "http://localhost:4000/auth/callback", // change to your domain when deploying,
    postLogoutRedirectUrl: "http://localhost:4000/", // The postLogoutRedirectUrl is the URL where the user will be redirected after successfully logging out from Civic's auth server.
  };

  app.use(cookieParser());

  // Tell Civic how to get cookies from your node server
  class ExpressCookieStorage extends CookieStorage {
    protected override settings = {
      secure: false,
      httpOnly: true,
      sameSite: "lax" as const,
      path: "/",
      expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days from now
    }; // Add settings manually

    constructor(private req: Request, private res: Response) {
      super({ secure: false });
    }

    async get(key: string): Promise<string | null> {
      return Promise.resolve(this.req.cookies[key] ?? null);
    }

    async set(key: string, value: string): Promise<void> {
      this.res.cookie(key, value, this.settings); // Use settings defined in this class
    }

    async delete(key: string): Promise<void> {
      this.res.clearCookie(key, this.settings); // Use settings defined in this class
    }
  }

  app.use((req: Request, res: Response, next: NextFunction) => {
    // add an instance of the cookie storage and civicAuth api to each request
    req.storage = new ExpressCookieStorage(req, res);
    req.civicAuth = new CivicAuth(req.storage, config);
    next();
  });

  app.get("/", async (req, res) => {
    if (!req.civicAuth) {
      res.status(500).send("CivicAuth is not initialized.");
      return;
    }
    const url = await req.civicAuth.buildLoginUrl({
      scopes: ["openid", "wallet", "email", "profile"],
    });

    res.redirect(url.toString());
  });

  const asyncHandler =
    (fn: Function) => (req: Request, res: Response, next: NextFunction) =>
      Promise.resolve(fn(req, res, next)).catch(next);

  app.get(
    "/auth/logout",
    asyncHandler(async (req: Request, res: Response) => {
      if (!req.civicAuth || !req.storage) {
        return res.status(500).send("CivicAuth or storage not initialized.");
      }

      // Clear cookies from your app
      for (const key of Object.keys(req.cookies)) {
        await req.storage.delete(key);
      }

      res.status(200).send("Logout successfully.");
    })
  );

  app.get("/auth/callback", async (req: Request, res: Response) => {
    const { code, state } = req.query as { code: string; state: string };

    if (!req.civicAuth) {
      res.status(500).send("CivicAuth is not initialized.");
      return;
    }

    try {
      await req.civicAuth.resolveOAuthAccessCode(code, state);
      res.redirect("http://localhost/rs2.cgi");
    } catch (err) {
      console.error("Auth callback error:", err);
      res.status(500).send("Failed to complete login.");
    }
  });

  const authMiddleware: RequestHandler = (
    req: Request,
    res: Response,
    next: NextFunction
  ) => {
    if (!req.civicAuth) {
      res.status(401).send("Unauthorized");
      return;
    }
    req.civicAuth
      .isLoggedIn()
      .then((loggedIn) => {
        if (!loggedIn) {
          res.status(401).send("Unauthorized");
          return;
        }
        next();
      })
      .catch((err) => {
        next(err);
      });
  };

  // Apply authentication middleware to any routes that need it
  app.use("/auth", authMiddleware);

  // Usage
  app.get(
    "/auth/profile",
    asyncHandler(async (req: Request, res: Response) => {
      if (!req.civicAuth) {
        return res.status(500).send("CivicAuth is not initialized.");
      }

      const loggedIn = await req.civicAuth.isLoggedIn();
      if (!loggedIn) {
        return res.status(401).send("Not logged in.");
      }

      const user = await req.civicAuth.getUser();
      console.log("Solana Wallet Address:", user?.email, {
        email: user.email,
        id: user?.id,
        name: user?.name,
        ...user,
      });

      res.json({
        message: "Authenticated profile",
        user: {
          email: user.email,
          id: user?.id,
          name: user?.name,
          ...user,
        },
      });
    })
  );

  app.listen(4000, async () => {
    console.log(`Server is running at: "http://localhost:4000"`);
  });
})();
