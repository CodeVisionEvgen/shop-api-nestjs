import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { User } from '../../src/user/entities/user.entity';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { JwtAuth } from './entities/jwt-auth.entity';
import { RefreshTokenStrategy } from '../../strategies/refreshToken.strategy';
import { UserModule } from '../../src/user/user.module';
import { MailerModule } from '@nestjs-modules/mailer';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MailerAsyncConfig } from 'configs/mailer.config';
import { EmailValidation } from './entities/email-validation.entity';
import { GoogleStrategy } from 'strategies/google.strategy';

@Module({
  controllers: [AuthController],
  providers: [AuthService, RefreshTokenStrategy, GoogleStrategy],
  imports: [
    TypeOrmModule.forFeature([User, JwtAuth, EmailValidation]),
    JwtModule,
    UserModule,
    MailerModule.forRootAsync({
      useFactory: MailerAsyncConfig,
      imports: [ConfigModule],
      inject: [ConfigService],
    }),
  ],
})
export class AuthModule {}
