import jwt from "jsonwebtoken";
import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockTriggers } from "../__tests__/mockTriggers";
import { UUID } from "../__tests__/patterns";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { JwtTokenGenerator, type TokenGenerator } from "./tokenGenerator";
import type { Triggers } from "./triggers";
import { attributeValue } from "./userPoolService";

const originalDate = new Date(2022, 4, 30, 17, 30, 0, 0);
const ONE_MINUTE = 60;
const ONE_HOUR = ONE_MINUTE * 60;
const ONE_DAY = ONE_HOUR * 24;
const SEVEN_DAYS = ONE_DAY * 7;

describe("JwtTokenGenerator", () => {
  let mockTriggers: MockedObject<Triggers>;
  let tokenGenerator: TokenGenerator;

  const user = TDB.user();
  const clock = new ClockFake(originalDate);

  beforeEach(() => {
    mockTriggers = newMockTriggers();
    tokenGenerator = new JwtTokenGenerator(clock, mockTriggers, {
      IssuerDomain: "http://example.com",
    });
  });

  describe("TokenGeneration lambda is configured (V1)", () => {
    it("can add and override claims to the id token", async () => {
      mockTriggers.enabled.mockImplementation((name) => {
        return name === "PreTokenGeneration";
      });
      mockTriggers.preTokenGeneration.mockResolvedValue({
        claimsOverrideDetails: {
          claimsToAddOrOverride: {
            newclaim: "value",
            email: "something else",
          },
        },
      });

      const tokens = await tokenGenerator.generate(
        TestContext,
        user,
        [],
        TDB.appClient(),
        { client: "metadata" },
        "RefreshTokens",
      );

      // id token has new claim added
      expect(jwt.decode(tokens.IdToken)).toMatchObject({
        newclaim: "value",
        email: "something else",
      });

      // access and refresh tokens cannot be changed by the trigger
      expect(jwt.decode(tokens.AccessToken)).not.toMatchObject({
        newclaim: "value",
        email: "something else",
      });
      expect(jwt.decode(tokens.RefreshToken)).not.toMatchObject({
        newclaim: "value",
        email: "something else",
      });
    });

    it("V1 behavior unchanged when explicitly using V1_0", async () => {
      mockTriggers.enabled.mockImplementation((name) => {
        return name === "PreTokenGeneration";
      });
      mockTriggers.preTokenGeneration.mockResolvedValue({
        claimsOverrideDetails: {
          claimsToAddOrOverride: {
            newclaim: "value",
          },
        },
      });

      const tokens = await tokenGenerator.generate(
        TestContext,
        user,
        [],
        TDB.appClient(),
        { client: "metadata" },
        "RefreshTokens",
        "V1_0",
      );

      // id token has new claim added
      expect(jwt.decode(tokens.IdToken)).toMatchObject({
        newclaim: "value",
      });

      // access token should not have the new claim
      expect(jwt.decode(tokens.AccessToken)).not.toMatchObject({
        newclaim: "value",
      });
    });

    it("can suppress claims in the id token", async () => {
      mockTriggers.enabled.mockImplementation((name) => {
        return name === "PreTokenGeneration";
      });
      mockTriggers.preTokenGeneration.mockResolvedValue({
        claimsOverrideDetails: {
          claimsToSuppress: ["email"],
        },
      });

      const tokens = await tokenGenerator.generate(
        TestContext,
        user,
        [],
        TDB.appClient(),
        { client: "metadata" },
        "RefreshTokens",
      );

      // id token has new claim added
      expect(jwt.decode(tokens.IdToken)).not.toHaveProperty("email");

      // access and refresh tokens cannot be changed by the trigger
      expect(jwt.decode(tokens.AccessToken)).not.toHaveProperty("email");
      expect(jwt.decode(tokens.RefreshToken)).toHaveProperty(
        "email",
        attributeValue("email", user.Attributes),
      );
    });

    it("suppresses claims that are also overridden", async () => {
      mockTriggers.enabled.mockImplementation((name) => {
        return name === "PreTokenGeneration";
      });
      mockTriggers.preTokenGeneration.mockResolvedValue({
        claimsOverrideDetails: {
          claimsToAddOrOverride: {
            email: "something else",
          },
          claimsToSuppress: ["email"],
        },
      });

      const tokens = await tokenGenerator.generate(
        TestContext,
        user,
        [],
        TDB.appClient(),
        { client: "metadata" },
        "RefreshTokens",
      );

      // id token has new claim added
      expect(jwt.decode(tokens.IdToken)).not.toHaveProperty("email");

      // access and refresh tokens cannot be changed by the trigger
      expect(jwt.decode(tokens.AccessToken)).not.toHaveProperty("email");
      expect(jwt.decode(tokens.RefreshToken)).toHaveProperty(
        "email",
        attributeValue("email", user.Attributes),
      );
    });

    describe.each([
      "acr",
      "amr",
      "aud",
      "at_hash",
      "auth_time",
      "azp",
      "cognito:username",
      "exp",
      "iat",
      "identities",
      "iss",
      "jti",
      "nbf",
      "nonce",
      "origin_jti",
      "sub",
      "token_use",
    ])("reserved claim %s", (claim) => {
      it("cannot override a reserved claim", async () => {
        mockTriggers.enabled.mockImplementation((name) => {
          return name === "PreTokenGeneration";
        });
        mockTriggers.preTokenGeneration.mockResolvedValue({
          claimsOverrideDetails: {
            claimsToAddOrOverride: {
              [claim]: "value",
            },
          },
        });

        const tokens = await tokenGenerator.generate(
          TestContext,
          user,
          [],
          TDB.appClient(),
          { client: "metadata" },
          "RefreshTokens",
        );

        expect(jwt.decode(tokens.IdToken)).not.toMatchObject({
          [claim]: "value",
        });
      });
    });
  });

  describe("TokenGeneration lambda is configured (V2)", () => {
    it("can add claims to access token via V2 response", async () => {
      mockTriggers.enabled.mockImplementation((name) => {
        return name === "PreTokenGeneration";
      });
      mockTriggers.preTokenGeneration.mockResolvedValue({
        claimsAndScopeOverrideDetails: {
          accessTokenGeneration: {
            claimsToAddOrOverride: {
              "custom:role": "admin",
            },
          },
        },
      });

      const tokens = await tokenGenerator.generate(
        TestContext,
        user,
        [],
        TDB.appClient(),
        { client: "metadata" },
        "RefreshTokens",
        "V2_0",
      );

      // access token has new claim added
      expect(jwt.decode(tokens.AccessToken)).toMatchObject({
        "custom:role": "admin",
      });

      // id token should not have the access token claim
      expect(jwt.decode(tokens.IdToken)).not.toMatchObject({
        "custom:role": "admin",
      });
    });

    it("can add claims to id token via V2 response", async () => {
      mockTriggers.enabled.mockImplementation((name) => {
        return name === "PreTokenGeneration";
      });
      mockTriggers.preTokenGeneration.mockResolvedValue({
        claimsAndScopeOverrideDetails: {
          idTokenGeneration: {
            claimsToAddOrOverride: {
              "custom:org": "acme",
            },
          },
        },
      });

      const tokens = await tokenGenerator.generate(
        TestContext,
        user,
        [],
        TDB.appClient(),
        { client: "metadata" },
        "RefreshTokens",
        "V2_0",
      );

      // id token has new claim added
      expect(jwt.decode(tokens.IdToken)).toMatchObject({
        "custom:org": "acme",
      });

      // access token should not have the id token claim
      expect(jwt.decode(tokens.AccessToken)).not.toMatchObject({
        "custom:org": "acme",
      });
    });

    it("can add claims to both id and access tokens via V2 response", async () => {
      mockTriggers.enabled.mockImplementation((name) => {
        return name === "PreTokenGeneration";
      });
      mockTriggers.preTokenGeneration.mockResolvedValue({
        claimsAndScopeOverrideDetails: {
          idTokenGeneration: {
            claimsToAddOrOverride: {
              "custom:org": "acme",
            },
          },
          accessTokenGeneration: {
            claimsToAddOrOverride: {
              "custom:role": "admin",
            },
          },
        },
      });

      const tokens = await tokenGenerator.generate(
        TestContext,
        user,
        [],
        TDB.appClient(),
        { client: "metadata" },
        "RefreshTokens",
        "V2_0",
      );

      // id token has its claim
      expect(jwt.decode(tokens.IdToken)).toMatchObject({
        "custom:org": "acme",
      });
      expect(jwt.decode(tokens.IdToken)).not.toMatchObject({
        "custom:role": "admin",
      });

      // access token has its claim
      expect(jwt.decode(tokens.AccessToken)).toMatchObject({
        "custom:role": "admin",
      });
      expect(jwt.decode(tokens.AccessToken)).not.toMatchObject({
        "custom:org": "acme",
      });
    });

    it("can suppress claims in access token via V2 response", async () => {
      mockTriggers.enabled.mockImplementation((name) => {
        return name === "PreTokenGeneration";
      });
      mockTriggers.preTokenGeneration.mockResolvedValue({
        claimsAndScopeOverrideDetails: {
          accessTokenGeneration: {
            claimsToAddOrOverride: {
              "custom:role": "admin",
            },
            claimsToSuppress: ["custom:role"],
          },
        },
      });

      const tokens = await tokenGenerator.generate(
        TestContext,
        user,
        [],
        TDB.appClient(),
        { client: "metadata" },
        "RefreshTokens",
        "V2_0",
      );

      // claim should be suppressed even though it was also added
      expect(jwt.decode(tokens.AccessToken)).not.toHaveProperty("custom:role");
    });

    describe.each([
      "acr",
      "amr",
      "aud",
      "at_hash",
      "auth_time",
      "azp",
      "cognito:username",
      "exp",
      "iat",
      "identities",
      "iss",
      "jti",
      "nbf",
      "nonce",
      "origin_jti",
      "sub",
      "token_use",
      "client_id",
      "scope",
      "username",
    ])("reserved access token claim %s", (claim) => {
      it("cannot override a reserved claim in access token", async () => {
        mockTriggers.enabled.mockImplementation((name) => {
          return name === "PreTokenGeneration";
        });
        mockTriggers.preTokenGeneration.mockResolvedValue({
          claimsAndScopeOverrideDetails: {
            accessTokenGeneration: {
              claimsToAddOrOverride: {
                [claim]: "malicious_value",
              },
            },
          },
        });

        const tokens = await tokenGenerator.generate(
          TestContext,
          user,
          [],
          TDB.appClient(),
          { client: "metadata" },
          "RefreshTokens",
          "V2_0",
        );

        expect(jwt.decode(tokens.AccessToken)).not.toMatchObject({
          [claim]: "malicious_value",
        });
      });
    });

    it("handles empty V2 response gracefully", async () => {
      mockTriggers.enabled.mockImplementation((name) => {
        return name === "PreTokenGeneration";
      });
      mockTriggers.preTokenGeneration.mockResolvedValue({
        claimsAndScopeOverrideDetails: {},
      });

      const userPoolClient = TDB.appClient();

      const tokens = await tokenGenerator.generate(
        TestContext,
        user,
        [],
        userPoolClient,
        { client: "metadata" },
        "RefreshTokens",
        "V2_0",
      );

      // tokens should be generated normally without modifications
      expect(jwt.decode(tokens.AccessToken)).toMatchObject({
        client_id: userPoolClient.ClientId,
        token_use: "access",
      });
      expect(jwt.decode(tokens.IdToken)).toMatchObject({
        "cognito:username": user.Username,
        token_use: "id",
      });
    });
  });

  describe("TokenGeneration lambda is not configured", () => {
    it("generates the default tokens", async () => {
      mockTriggers.enabled.mockReturnValue(false);

      const userPoolClient = TDB.appClient();

      const tokens = await tokenGenerator.generate(
        TestContext,
        user,
        [],
        userPoolClient,
        { client: "metadata" },
        "RefreshTokens",
      );

      expect(jwt.decode(tokens.AccessToken)).toEqual({
        auth_time: expect.any(Number),
        client_id: userPoolClient.ClientId,
        event_id: expect.stringMatching(UUID),
        exp: Math.floor(originalDate.getTime() / 1000) + ONE_DAY,
        iat: Math.floor(originalDate.getTime() / 1000),
        iss: `http://example.com/${userPoolClient.UserPoolId}`,
        jti: expect.stringMatching(UUID),
        scope: "aws.cognito.signin.user.admin",
        sub: attributeValue("sub", user.Attributes),
        token_use: "access",
        username: user.Username,
      });

      expect(jwt.decode(tokens.IdToken)).toEqual({
        "cognito:username": user.Username,
        aud: userPoolClient.ClientId,
        auth_time: expect.any(Number),
        email: attributeValue("email", user.Attributes),
        email_verified: false,
        event_id: expect.stringMatching(UUID),
        exp: Math.floor(originalDate.getTime() / 1000) + ONE_DAY,
        iat: Math.floor(originalDate.getTime() / 1000),
        iss: `http://example.com/${userPoolClient.UserPoolId}`,
        jti: expect.stringMatching(UUID),
        sub: attributeValue("sub", user.Attributes),
        token_use: "id",
      });

      expect(jwt.decode(tokens.RefreshToken)).toEqual({
        "cognito:username": user.Username,
        email: attributeValue("email", user.Attributes),
        exp: Math.floor(originalDate.getTime() / 1000) + SEVEN_DAYS,
        iat: Math.floor(originalDate.getTime() / 1000),
        iss: `http://example.com/${userPoolClient.UserPoolId}`,
        jti: expect.stringMatching(UUID),
      });
    });
  });

  describe("expiration configuration", () => {
    describe("no token validity configured", () => {
      it("generates default expiration times", async () => {
        mockTriggers.enabled.mockReturnValue(false);

        const userPoolClient = TDB.appClient({
          AccessTokenValidity: undefined,
          IdTokenValidity: undefined,
          RefreshTokenValidity: undefined,
          TokenValidityUnits: undefined,
        });

        const tokens = await tokenGenerator.generate(
          TestContext,
          user,
          [],
          userPoolClient,
          { client: "metadata" },
          "RefreshTokens",
        );

        expect((jwt.decode(tokens.AccessToken) as any).exp).toEqual(
          Math.floor(originalDate.getTime() / 1000) + ONE_DAY,
        );
        expect((jwt.decode(tokens.IdToken) as any).exp).toEqual(
          Math.floor(originalDate.getTime() / 1000) + ONE_DAY,
        );
        expect((jwt.decode(tokens.RefreshToken) as any).exp).toEqual(
          Math.floor(originalDate.getTime() / 1000) + SEVEN_DAYS,
        );
      });
    });

    describe("no token validity configured but has units configured", () => {
      it("generates default expiration times", async () => {
        mockTriggers.enabled.mockReturnValue(false);

        const userPoolClient = TDB.appClient({
          AccessTokenValidity: undefined,
          IdTokenValidity: undefined,
          RefreshTokenValidity: undefined,
          TokenValidityUnits: {
            AccessToken: "seconds",
            IdToken: "seconds",
            RefreshToken: "seconds",
          },
        });

        const tokens = await tokenGenerator.generate(
          TestContext,
          user,
          [],
          userPoolClient,
          { client: "metadata" },
          "RefreshTokens",
        );

        expect((jwt.decode(tokens.AccessToken) as any).exp).toEqual(
          Math.floor(originalDate.getTime() / 1000) + ONE_DAY,
        );
        expect((jwt.decode(tokens.IdToken) as any).exp).toEqual(
          Math.floor(originalDate.getTime() / 1000) + ONE_DAY,
        );
        expect((jwt.decode(tokens.RefreshToken) as any).exp).toEqual(
          Math.floor(originalDate.getTime() / 1000) + SEVEN_DAYS,
        );
      });
    });

    describe("token validity configured but no units configured", () => {
      it("generates uses configured validity times with default units", async () => {
        mockTriggers.enabled.mockReturnValue(false);

        const userPoolClient = TDB.appClient({
          AccessTokenValidity: 10,
          IdTokenValidity: 20,
          RefreshTokenValidity: 30,
          TokenValidityUnits: undefined,
        });

        const tokens = await tokenGenerator.generate(
          TestContext,
          user,
          [],
          userPoolClient,
          { client: "metadata" },
          "RefreshTokens",
        );

        expect((jwt.decode(tokens.AccessToken) as any).exp).toEqual(
          Math.floor(originalDate.getTime() / 1000) + 10 * ONE_HOUR,
        );
        expect((jwt.decode(tokens.IdToken) as any).exp).toEqual(
          Math.floor(originalDate.getTime() / 1000) + 20 * ONE_HOUR,
        );
        expect((jwt.decode(tokens.RefreshToken) as any).exp).toEqual(
          Math.floor(originalDate.getTime() / 1000) + 30 * ONE_DAY,
        );
      });
    });

    describe("token validity and units configured", () => {
      it("generates uses configured validity times with configured units", async () => {
        mockTriggers.enabled.mockReturnValue(false);

        const userPoolClient = TDB.appClient({
          AccessTokenValidity: 10,
          IdTokenValidity: 20,
          RefreshTokenValidity: 30,
          TokenValidityUnits: {
            AccessToken: "seconds",
            IdToken: "minutes",
            RefreshToken: "hours",
          },
        });

        const tokens = await tokenGenerator.generate(
          TestContext,
          user,
          [],
          userPoolClient,
          { client: "metadata" },
          "RefreshTokens",
        );

        expect((jwt.decode(tokens.AccessToken) as any).exp).toEqual(
          Math.floor(originalDate.getTime() / 1000) + 10,
        );
        expect((jwt.decode(tokens.IdToken) as any).exp).toEqual(
          Math.floor(originalDate.getTime() / 1000) + 20 * ONE_MINUTE,
        );
        expect((jwt.decode(tokens.RefreshToken) as any).exp).toEqual(
          Math.floor(originalDate.getTime() / 1000) + 30 * ONE_HOUR,
        );
      });
    });
  });

  describe("groups", () => {
    it("does not include a cognito:groups claim if the user has no groups", async () => {
      mockTriggers.enabled.mockReturnValue(false);

      const userPoolClient = TDB.appClient({
        AccessTokenValidity: 10,
        IdTokenValidity: 20,
        RefreshTokenValidity: 30,
        TokenValidityUnits: {
          AccessToken: "seconds",
          IdToken: "minutes",
          RefreshToken: "hours",
        },
      });

      const tokens = await tokenGenerator.generate(
        TestContext,
        user,
        [],
        userPoolClient,
        { client: "metadata" },
        "RefreshTokens",
      );

      expect(
        (jwt.decode(tokens.AccessToken) as any)["cognito:groups"],
      ).toBeUndefined();
      expect(
        (jwt.decode(tokens.IdToken) as any)["cognito:groups"],
      ).toBeUndefined();
    });

    it("includes a cognito:groups claim with the user's groups", async () => {
      mockTriggers.enabled.mockReturnValue(false);

      const userPoolClient = TDB.appClient({
        AccessTokenValidity: 10,
        IdTokenValidity: 20,
        RefreshTokenValidity: 30,
        TokenValidityUnits: {
          AccessToken: "seconds",
          IdToken: "minutes",
          RefreshToken: "hours",
        },
      });

      const tokens = await tokenGenerator.generate(
        TestContext,
        user,
        ["group1", "group2"],
        userPoolClient,
        { client: "metadata" },
        "RefreshTokens",
      );

      expect((jwt.decode(tokens.AccessToken) as any)["cognito:groups"]).toEqual(
        ["group1", "group2"],
      );
      expect((jwt.decode(tokens.IdToken) as any)["cognito:groups"]).toEqual([
        "group1",
        "group2",
      ]);
    });
  });
});
