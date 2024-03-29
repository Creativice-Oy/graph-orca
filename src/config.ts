import {
  IntegrationExecutionContext,
  IntegrationValidationError,
  IntegrationInstanceConfigFieldMap,
  IntegrationInstanceConfig,
} from '@jupiterone/integration-sdk-core';
import { createAPIClient } from './client';

/**
 * A type describing the configuration fields required to execute the
 * integration for a specific account in the data provider.
 *
 * When executing the integration in a development environment, these values may
 * be provided in a `.env` file with environment variables. For example:
 *
 * - `CLIENT_SECRET=abc` becomes `instance.config.clientSecret = 'abc'`
 *
 * Environment variables are NOT used when the integration is executing in a
 * managed environment. For example, in JupiterOne, users configure
 * `instance.config` in a UI.
 */
export const instanceConfigFields: IntegrationInstanceConfigFieldMap = {
  clientSecret: {
    type: 'string',
    mask: true,
  },
  clientEmail: {
    type: 'string',
    mask: true,
  },
  clientBaseUrl: {
    type: 'string',
  },
  clientMaxTimeout: {
    type: 'string',
  },
};

/**
 * Properties provided by the `IntegrationInstance.config`. This reflects the
 * same properties defined by `instanceConfigFields`.
 */
export interface IntegrationConfig extends IntegrationInstanceConfig {
  /**
   * The provider API client secret used to authenticate requests.
   */
  clientSecret: string;

  /**
   * The client email at the provider.
   */
  clientEmail: string;

  /**
   * The client base url at the provider.
   */
  clientBaseUrl: string;

  /**
   * The client max timeout for bulk downloads in ms.
   */
  clientMaxTimeout: number;
}

export async function validateInvocation(
  context: IntegrationExecutionContext<IntegrationConfig>,
) {
  const {
    logger,
    instance: { config },
  } = context;

  if (!config.clientSecret || !config.clientEmail || !config.clientBaseUrl) {
    throw new IntegrationValidationError(
      'Config requires all of {clientSecret, clientEmail, clientBaseUrl}',
    );
  }

  const apiClient = createAPIClient(config, logger);
  await apiClient.verifyAuthentication();
}
