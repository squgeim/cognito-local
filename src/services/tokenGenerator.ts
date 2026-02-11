import type { StringMap } from "aws-lambda/trigger/cognito-user-pool-trigger/_common";
import type { GroupOverrideDetails } from "aws-lambda/trigger/cognito-user-pool-trigger/pre-token-generation";
import type { TimeUnitsType } from "aws-sdk/clients/cognitoidentityserviceprovider";
import jwt, { type SignOptions } from "jsonwebtoken";
import type { StringValue, UnitAnyCase } from "ms";
import * as uuid from "uuid";
import PrivateKey from "../keys/cognitoLocal.private.json";
import type { AppClient } from "./appClient";
import type { Clock } from "./clock";
import type { Context } from "./context";
import type {
  PreTokenGenerationLambdaVersion,
  PreTokenGenerationTriggerResponse,
  PreTokenGenerationV2TriggerResponse,
} from "./lambda";
import type { Triggers } from "./triggers";
import {
  attributesToRecord,
  attributeValue,
  customAttributes,
  type User,
} from "./userPoolService";

export interface TokenConfig {
  IssuerDomain?: string;
}

export interface Token {
  client_id: string;
  iss: string;
  sub: string;
  token_use: string;
  username: string;
  event_id: string;
  scope: string;
  auth_time: Date;
  jti: string;
}

interface TokenOverrides {
  claimsToAddOrOverride?: StringMap | undefined;
  claimsToSuppress?: string[] | undefined;
  groupOverrideDetails?: GroupOverrideDetails | undefined;
}

const RESERVED_CLAIMS = [
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
];

// Additional reserved claims for access tokens
const ACCESS_TOKEN_RESERVED_CLAIMS = [
  ...RESERVED_CLAIMS,
  "client_id",
  "scope",
  "username",
];

type RawToken = Record<
  string,
  string | number | boolean | undefined | readonly string[]
>;

const applyTokenOverrides = (
  token: RawToken,
  overrides: TokenOverrides,
  reservedClaims: readonly string[] = RESERVED_CLAIMS,
): RawToken => {
  // TODO: support group overrides

  const claimsToSuppress = (overrides?.claimsToSuppress ?? []).filter(
    (claim) => !reservedClaims.includes(claim),
  );

  const claimsToOverride = Object.entries(
    overrides?.claimsToAddOrOverride ?? [],
  ).filter(([claim]) => !reservedClaims.includes(claim));

  return Object.fromEntries(
    [...Object.entries(token), ...claimsToOverride].filter(
      ([claim]) => !claimsToSuppress.includes(claim),
    ),
  );
};

// Type guard to check if the response is a V2 response
const isV2Response = (
  response: PreTokenGenerationTriggerResponse,
): response is PreTokenGenerationV2TriggerResponse => {
  return "claimsAndScopeOverrideDetails" in response;
};

export interface Tokens {
  readonly AccessToken: string;
  readonly IdToken: string;
  readonly RefreshToken: string;
}

export interface TokenGenerator {
  generate(
    ctx: Context,
    user: User,
    userGroups: readonly string[],
    userPoolClient: AppClient,
    clientMetadata: Record<string, string> | undefined,
    source:
      | "AuthenticateDevice"
      | "Authentication"
      | "HostedAuth"
      | "NewPasswordChallenge"
      | "RefreshTokens",
    lambdaVersion?: PreTokenGenerationLambdaVersion,
  ): Promise<Tokens>;
}

function assertUnitAnyCase(unit: string): asserts unit is UnitAnyCase {
  if (!["seconds", "minutes", "hours", "days"].includes(unit)) {
    throw new Error(`Invalid unit: ${unit}`);
  }
}

const formatExpiration = (
  duration: number | undefined,
  unit: TimeUnitsType,
  fallback: StringValue,
): StringValue => {
  if (duration === undefined) {
    return fallback;
  }

  assertUnitAnyCase(unit);

  return `${duration}${unit}`;
};

export class JwtTokenGenerator implements TokenGenerator {
  private readonly clock: Clock;
  private readonly triggers: Triggers;
  private readonly tokenConfig: TokenConfig;

  public constructor(
    clock: Clock,
    triggers: Triggers,
    tokenConfig: TokenConfig,
  ) {
    this.clock = clock;
    this.triggers = triggers;
    this.tokenConfig = tokenConfig;
  }

  public async generate(
    ctx: Context,
    user: User,
    userGroups: readonly string[],
    userPoolClient: AppClient,
    clientMetadata: Record<string, string> | undefined,
    source:
      | "AuthenticateDevice"
      | "Authentication"
      | "HostedAuth"
      | "NewPasswordChallenge"
      | "RefreshTokens",
    lambdaVersion: PreTokenGenerationLambdaVersion = "V1_0",
  ): Promise<Tokens> {
    const eventId = uuid.v4();
    const authTime = Math.floor(this.clock.get().getTime() / 1000);
    const sub = attributeValue("sub", user.Attributes);
    const currentScopes = ["aws.cognito.signin.user.admin"]; // TODO: scopes

    let accessToken: RawToken = {
      auth_time: authTime,
      client_id: userPoolClient.ClientId,
      event_id: eventId,
      iat: authTime,
      jti: uuid.v4(),
      scope: currentScopes.join(" "),
      sub,
      token_use: "access",
      username: user.Username,
    };
    let idToken: RawToken = {
      "cognito:username": user.Username,
      auth_time: authTime,
      email: attributeValue("email", user.Attributes),
      email_verified: Boolean(
        attributeValue("email_verified", user.Attributes) ?? false,
      ),
      event_id: eventId,
      iat: authTime,
      jti: uuid.v4(),
      sub,
      token_use: "id",
      ...attributesToRecord(customAttributes(user.Attributes)),
    };

    if (userGroups.length) {
      accessToken["cognito:groups"] = userGroups;
      idToken["cognito:groups"] = userGroups;
    }

    if (this.triggers.enabled("PreTokenGeneration")) {
      const result = await this.triggers.preTokenGeneration(ctx, {
        clientId: userPoolClient.ClientId,
        clientMetadata,
        source,
        userAttributes: user.Attributes,
        username: user.Username,
        groupConfiguration: {
          // TODO: this should be populated from the user's groups
          groupsToOverride: undefined,
          iamRolesToOverride: undefined,
          preferredRole: undefined,
        },
        userPoolId: userPoolClient.UserPoolId,
        lambdaVersion,
        scopes: currentScopes,
      });

      if (isV2Response(result)) {
        // V2 response: apply overrides to both ID and access tokens
        if (result.claimsAndScopeOverrideDetails?.idTokenGeneration) {
          idToken = applyTokenOverrides(
            idToken,
            result.claimsAndScopeOverrideDetails.idTokenGeneration,
            RESERVED_CLAIMS,
          );
        }
        if (result.claimsAndScopeOverrideDetails?.accessTokenGeneration) {
          accessToken = applyTokenOverrides(
            accessToken,
            result.claimsAndScopeOverrideDetails.accessTokenGeneration,
            ACCESS_TOKEN_RESERVED_CLAIMS,
          );
        }
      } else {
        // V1 response: only apply overrides to ID token
        idToken = applyTokenOverrides(
          idToken,
          result.claimsOverrideDetails,
          RESERVED_CLAIMS,
        );
      }
    }

    const issuer = `${this.tokenConfig.IssuerDomain}/${userPoolClient.UserPoolId}`;

    return {
      AccessToken: jwt.sign(accessToken, PrivateKey.pem, {
        algorithm: "RS256",
        issuer,
        expiresIn: formatExpiration(
          userPoolClient.AccessTokenValidity,
          userPoolClient.TokenValidityUnits?.AccessToken ?? "hours",
          "24h",
        ),
        keyid: "CognitoLocal",
      } satisfies SignOptions),
      IdToken: jwt.sign(idToken, PrivateKey.pem, {
        algorithm: "RS256",
        issuer,
        expiresIn: formatExpiration(
          userPoolClient.IdTokenValidity,
          userPoolClient.TokenValidityUnits?.IdToken ?? "hours",
          "24h",
        ),
        audience: userPoolClient.ClientId,
        keyid: "CognitoLocal",
      } satisfies SignOptions),
      // this content is for debugging purposes only
      // in reality token payload is encrypted and uses different algorithm
      RefreshToken: jwt.sign(
        {
          "cognito:username": user.Username,
          email: attributeValue("email", user.Attributes),
          iat: authTime,
          jti: uuid.v4(),
        },
        PrivateKey.pem,
        {
          algorithm: "RS256",
          issuer,
          expiresIn: formatExpiration(
            userPoolClient.RefreshTokenValidity,
            userPoolClient.TokenValidityUnits?.RefreshToken ?? "days",
            "7d",
          ),
        } satisfies SignOptions,
      ),
    };
  }
}
