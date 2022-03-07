import { getForbidden, getInternalError, getUnauthorized } from '@verdaccio/commons-api';
import { AuthCallback, IPluginAuth, Logger } from '@verdaccio/types';
import { Client, InvalidCredentialsError } from 'ldapts';

export interface LdapConfig {
  url: string;
  baseDN: string;
  groupName?: string;
}

export default class LdapPlugin implements IPluginAuth<LdapConfig> {
  private config: LdapConfig;
  private logger: Logger;

  public constructor(config: LdapConfig, opts: { logger: Logger }) {
    this.config = config;
    this.logger = opts.logger;
  }

  public async authenticate(user: string, password: string, cb: AuthCallback): Promise<void> {
    const client = new Client({
      url: this.config.url
    });

    const dn = `uid=${user},${this.config.baseDN}`;

    try {
      await client.bind(dn, password);

      if (this.config.groupName) {
        const { searchEntries } = await client.search(dn, {
          scope: 'sub',
          filter: `(&(uid=${user})(memberOf=cn=${this.config.groupName},${this.config.baseDN}))`
        });

        if (searchEntries.length === 0) {
          const msg = `LDAP - User ${user} not in Group ${this.config.groupName}`;
          this.logger.warn(msg);
          return cb(getForbidden(msg), false);
        }
      }

      return cb(null, [user]);
    } catch (error) {
      if (error instanceof InvalidCredentialsError) {
        return cb(getUnauthorized('Invalid credentials'), false);
      }

      this.logger.warn(`LDAP - Could not bind: ${error}`);
      return cb(getInternalError((error as unknown) as string), false);
    } finally {
      client.unbind();
    }
  }
}
