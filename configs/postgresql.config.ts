import { ConfigService } from '@nestjs/config';
import { TypeOrmModuleOptions } from '@nestjs/typeorm';

export const PostgreSQLConfig = (
  configService: ConfigService,
): TypeOrmModuleOptions => {
  return {
    type: 'postgres',
    host: configService.get('POSTGRESQL_HOST') || 'localhost',
    port: +configService.get('POSTGRESQL_PORT') || 5432,
    username: configService.get('POSTGRESQL_USERNAME'),
    password: configService.get('POSTGRESQL_PASSWORD'),
    database: configService.get('POSTGRESQL_DATABASE'),
    synchronize: true,
  };
};
