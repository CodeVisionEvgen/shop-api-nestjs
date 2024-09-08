import { Module } from '@nestjs/common';
import { UserModule } from './user/user.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { PostgreSQLConfig } from '../configs/postgresql.config';
import { ProductModule } from './product/product.module';
import { AuthModule } from './auth/auth.module';
import { ImageKitModule } from 'imagekit-nestjs';
import { ImageKitConfig } from '../configs/imagekit.config';

// import { JwtModule } from '@nestjs/jwt';
// import { JwtRegisterAsyncOptions } from 'configs/jwt-default.config';
@Module({
  imports: [
    UserModule,
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    TypeOrmModule.forRootAsync({
      useFactory: PostgreSQLConfig,
      inject: [ConfigService],
      // imports: [ConfigService],
    }),
    ImageKitModule.forRootAsync({
      inject: [ConfigService],
      isGlobal: true,
      useFactory: ImageKitConfig,
    }),
    ProductModule,
    AuthModule,
  ],
})
export class AppModule {}
