import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { User } from '../../src/user/entities/user.entity';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { JwtAuth } from './entities/jwt-auth.entity';
import { RefreshTokenStrategy } from '../../strategies/refreshToken.strategy';
import { UserModule } from '../../src/user/user.module';

@Module({
  controllers: [AuthController],
  providers: [AuthService, RefreshTokenStrategy],
  imports: [TypeOrmModule.forFeature([User, JwtAuth]), JwtModule, UserModule],
})
export class AuthModule {}
