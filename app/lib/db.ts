import sql, { ConnectionPool, IResult } from 'mssql';
import fs from 'fs';
import path from 'path';

// Environment variable validation
function validateConfig() {
  const required = ['DB_SERVER', 'DB_NAME', 'DB_USER', 'DB_PWD'];
  const missing = required.filter(key => !process.env[key]);
  
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
}

export const db = {
  pool: null as ConnectionPool | null,
  connecting: null as Promise<void> | null,
  
  connect: async function (): Promise<void> {
    // Validate environment variables first
    validateConfig();
    
    // For VPN connections where server is accessed via IP:
    // 1. Add the IP and hostname to your hosts file (/etc/hosts or C:\Windows\System32\drivers\etc\hosts)
    // Example: 10.0.0.100 sql-server.internal
    // 2. Use that hostname in your DB_SERVER environment variable
    const config = {
      server: process.env.DB_SERVER!,
      port: 1433,
      database: process.env.DB_NAME!,
      user: process.env.DB_USER!,
      password: process.env.DB_PWD!,
      options: {
        trustServerCertificate: true,
        encrypt: true,
        enableArithAbort: true,
        connectionTimeout: 30000,
        requestTimeout: 30000
      }
    };
    this.pool = await sql.connect(config);
  },

  close: async function(): Promise<void> {
    if (this.pool) {
      await this.pool.close();
      this.pool = null;
    }
    this.connecting = null;
  },

  isConnected: function(): boolean {
    return this.pool !== null && this.pool.connected;
  },

  ensureConnection: async function(): Promise<void> {
    if (this.isConnected()) return;
    
    if (this.connecting) {
      await this.connecting;
      return;
    }
    
    this.connecting = this.connect();
    try {
      await this.connecting;
    } catch (error) {
      this.connecting = null;
      throw error;
    }
    this.connecting = null;
  },

  readSqlFile: function (filePath: string): string | null {
    const fullPath = path.join('app', 'queries', `${filePath}.sql`);
    try {
      return fs.readFileSync(fullPath, { encoding: 'utf8' });
    } catch (error) {
      // console.error('Failed to read the SQL file:', error);
      return null;
    }
  },
  query: async function (queryString: string, params: { [key: string]: any } = {}): Promise<IResult<any>> {
    await this.ensureConnection();
    const request = this.pool!.request();
    for (const key in params) {
      request.input(key, params[key]);
    }
    return await request.query(queryString);
  },
  queryFromPath: async function <T>(filePath: string, params: { [key: string]: any } = {}): Promise<T[]> {
    try {
      const queryString = this.readSqlFile(filePath);
      if (!queryString) throw new Error('Could not read sql from path: ' + filePath);
      const result = await this.query(queryString, params);
      return this.parseJsonFields(result.recordset);
    } catch (error) {
      // console.error('Error executing query from path:', error);
      throw error;
    }
  },
  parseJsonFields: function (data: any[]): any[] {
    return data.map(record => this.parseJsonRecursively(record));
  },
  parseJsonRecursively: function (obj: any): any {
    if (typeof obj === 'string' && this.isJsonString(obj)) {
      return this.parseJsonRecursively(JSON.parse(obj));
    } else if (Array.isArray(obj)) {
      return obj.map(item => this.parseJsonRecursively(item));
    } else if (obj !== null && typeof obj === 'object') {
      for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
          obj[key] = this.parseJsonRecursively(obj[key]);
        }
      }
      return obj;
    } else {
      return obj;
    }
  },
  isJsonString: function (str: string): boolean {
    try {
      JSON.parse(str);
      return true;
    } catch (e) {
      return false;
    }
  }
};