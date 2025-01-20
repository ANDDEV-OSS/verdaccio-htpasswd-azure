import type { pluginUtils } from '@verdaccio/core';

import HTPasswdAzure, { HTPasswdAzureConfig } from './htpasswdAzure';

export default function (config: HTPasswdAzureConfig, params: pluginUtils.PluginOptions): HTPasswdAzure {
  return new HTPasswdAzure(config, params);
}

export { HTPasswdAzure, HTPasswdAzureConfig };