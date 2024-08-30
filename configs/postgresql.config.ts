import { ConfigService } from '@nestjs/config';
import { TypeOrmModuleOptions } from '@nestjs/typeorm';
import { JwtAuth } from '../src/auth/entities/jwt-auth.entity';
import { User } from '../src/user/entities/user.entity';

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
    entities: [User, JwtAuth],
    synchronize: true,
  };
};
